import contextlib
import io
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netrunner import interaction, main as cli
from netrunner.core.models import CommandResult
from netrunner.sequences.port_scan import run_port_scan
from netrunner.tools.nmap import build_nmap_request
from netrunner.tools.rustscan import InvalidPortScanTarget, build_rustscan_request
from netrunner.workflows import run_rustscan


def ipv4_answer(address="192.0.2.1"):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))


def ipv6_answer(address="2001:db8::1"):
    return (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0))


def run_without_animation(subject, function, *args, **kwargs):
    return function(*args)


class PortScanTargetTests(unittest.TestCase):
    def setUp(self):
        # Every test is offline, including unexpected code paths.
        self.resolver = self.enterContext(patch("socket.getaddrinfo"))
        self.resolver.side_effect = AssertionError("Unexpected DNS lookup")
        self.process = self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("Unexpected external command"))
        )

    def test_ip_literals_do_not_require_dns_and_preserve_scan_flags(self):
        for target, expected in (
            ("192.0.2.1", "192.0.2.1"),
            ("::1", "::1"),
            ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
        ):
            with self.subTest(target=target):
                request = build_rustscan_request(target)
                self.assertEqual(request.program, "rustscan")
                # Configuration isolation is explicitly deferred for this phase.
                self.assertEqual(
                    request.arguments,
                    ["-a", expected, "--top", "--greppable", "--no-banner"],
                )
        self.resolver.assert_not_called()
        self.process.assert_not_called()

    def test_valid_hostnames_resolve_to_one_numeric_target(self):
        self.resolver.side_effect = None
        self.resolver.return_value = [ipv4_answer()]
        for target, expected_query in (
            ("localhost", "localhost"),
            ("router-1", "router-1"),
            ("3com.example", "3com.example"),
            ("LAB.Example.", "LAB.Example."),
            ("b\u00fccher.example", "xn--bcher-kva.example"),
            ("b\u00fccher", "xn--bcher-kva"),
            ("bu\u0308cher.example", "xn--bcher-kva.example"),
            ("lab\u3002example\uff61", "lab.example."),
            ("la\u00adb.example", "lab.example"),
            ("a" * 63 + ".example", "a" * 63 + ".example"),
            (".".join(["a" * 63] * 3 + ["b" * 61]), ".".join(["a" * 63] * 3 + ["b" * 61])),
            (".".join(["a" * 63] * 3 + ["b" * 61]) + ".", ".".join(["a" * 63] * 3 + ["b" * 61]) + "."),
        ):
            with self.subTest(target=target):
                request = build_rustscan_request(target)
                self.assertEqual(request.arguments[1], "192.0.2.1")
                self.resolver.assert_called_with(expected_query, None, type=socket.SOCK_STREAM)
        self.process.assert_not_called()

    def test_hostname_can_resolve_to_ipv6_and_duplicate_answers_are_not_multiple_targets(self):
        self.resolver.side_effect = None
        self.resolver.return_value = [ipv6_answer(), ipv6_answer()]
        self.assertEqual(build_rustscan_request("lab.example").arguments[1], "2001:db8::1")

    def test_invalid_syntax_rejected_before_dns_or_execution(self):
        for target in (
            "", " ", " lab.example", "lab.example ",
            "192.0.2.0/24", "2001:db8::/64",
            "192.0.2.1,192.0.2.2", "one.example two.example",
            "one.example\ntwo.example", "one.example\ttwo.example",
            "192.0.2.*", "192.0.2.[1-4]", "[2001:db8::1]", "[::1]:80",
            "lab.example:80", "@targets.txt", "./targets.txt", "/tmp/targets.txt",
            "~/targets.txt", "file://targets.txt", "C:\\targets.txt",
            "--help", "-a", "--addresses=lab.example", "-iL targets.txt",
            "fe80::1%eth0", "999.0.0.1", "192.00.2.1",
            ".example", "lab..example", "-lab.example", "lab-.example",
            "_service.example", "lab.example;id", "lab.example\x00",
            "a" * 64 + ".example", ".".join(["a" * 63] * 4),
            ".".join(["a" * 63] * 3 + ["b" * 62]),
            # These characters normalize before the hostname-label checks.
            "one.example\uff0ctwo.example", "192.0.2.0\uff0f24",
            "\uff20targets.txt", ".\uff3ctargets.txt", "\uff0d\uff0dhelp",
            "\uff3b2001:db8::1\uff3d", "lab.example\uff1a80",
            "lab\u3002\u3002example", "lab.example\uff0e\uff0e", "lab\ud800.example",
        ):
            with self.subTest(target=target), patch("netrunner.workflows.run_command") as execute:
                with self.assertRaises(InvalidPortScanTarget):
                    run_rustscan(target)
                execute.assert_not_called()
        self.resolver.assert_not_called()
        self.process.assert_not_called()

    def test_ambiguous_or_unresolved_hostnames_fail_before_execution(self):
        for answers in (
            [],
            [ipv4_answer(), ipv4_answer("192.0.2.2")],
            [ipv4_answer(), ipv6_answer()],
        ):
            with self.subTest(answers=answers), patch("netrunner.workflows.run_command") as execute:
                self.resolver.side_effect = None
                self.resolver.return_value = answers
                with self.assertRaisesRegex(InvalidPortScanTarget, "specific IP address"):
                    run_rustscan("lab.example")
                execute.assert_not_called()

        self.resolver.side_effect = socket.gaierror("Not found")
        with patch("netrunner.workflows.run_command") as execute:
            with self.assertRaisesRegex(InvalidPortScanTarget, "could not be resolved"):
                run_rustscan("missing.example")
            execute.assert_not_called()

    def test_hostname_looking_file_is_never_passed_to_rustscan(self):
        self.resolver.side_effect = socket.gaierror("Not found")
        with tempfile.TemporaryDirectory() as directory, contextlib.chdir(directory):
            Path("targets.txt").write_text("192.0.2.1\n192.0.2.2\n")
            with patch("netrunner.workflows.run_command") as execute:
                with self.assertRaises(InvalidPortScanTarget):
                    run_rustscan("targets.txt")
                execute.assert_not_called()

    def test_same_address_is_used_for_rustscan_and_nmap(self):
        # A second DNS lookup would return another address; no second lookup is allowed.
        self.resolver.side_effect = [[ipv6_answer()], [ipv4_answer()]]
        requests = []

        def execute(request):
            requests.append(request)
            if request.program == "rustscan":
                stdout = "2001:db8::1 -> [80,443]\n"
            else:
                stdout = (
                    '<nmaprun><host><status state="up"/>'
                    '<address addr="2001:db8::1" addrtype="ipv6"/>'
                    '<ports><port protocol="tcp" portid="80">'
                    '<state state="open"/></port></ports></host></nmaprun>'
                )
            return CommandResult(request, stdout, "", 0)

        with patch("netrunner.workflows.run_command", side_effect=execute):
            result = run_port_scan("lab.example")

        self.resolver.assert_called_once()
        self.assertEqual([request.program for request in requests], ["rustscan", "nmap"])
        self.assertEqual(requests[0].arguments[1], "2001:db8::1")
        self.assertEqual(requests[1].arguments, ["-sV", "-oX", "-", "-6", "-p", "80,443", "2001:db8::1"])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.target, "lab.example")
        self.assertEqual(result.rustscan.target, "lab.example")
        self.assertEqual(result.nmap.target, "lab.example")
        self.assertEqual(result.nmap.resolved_ip, "2001:db8::1")
        self.process.assert_not_called()

    def test_ipv4_nmap_arguments_are_unchanged(self):
        request = build_nmap_request("192.0.2.1", [80])
        self.assertEqual(request.arguments, ["-sV", "-oX", "-", "-p", "80", "192.0.2.1"])

    def test_wrong_or_invalid_output_address_skips_nmap(self):
        for answer, reported in (
            (ipv4_answer(), "192.0.2.2"),
            (ipv6_answer(), "2001:db8::2"),
            (ipv4_answer(), "not-an-ip"),
        ):
            with self.subTest(address=answer[4][0], reported=reported):
                self.resolver.reset_mock()
                self.resolver.side_effect = None
                self.resolver.return_value = [answer]
                with (
                    patch(
                        "netrunner.workflows.run_command",
                        side_effect=lambda request: CommandResult(request, f"{reported} -> [80,443]", "", 0),
                    ) as execute,
                    patch("netrunner.sequences.port_scan.run_nmap") as nmap,
                ):
                    result = run_port_scan("lab.example")

                self.resolver.assert_called_once_with("lab.example", None, type=socket.SOCK_STREAM)
                execute.assert_called_once()
                self.assertEqual(execute.call_args.args[0].arguments[1], answer[4][0])
                nmap.assert_not_called()
                self.assertEqual(result.target, "lab.example")
                self.assertEqual(result.rustscan.target, "lab.example")
                self.assertEqual(result.rustscan.status, "error")
                self.assertEqual(result.rustscan.open_ports, [])
                self.assertEqual(result.status, "rustscan_error")
                self.assertIsNone(result.nmap)
        self.process.assert_not_called()

    def test_nmap_failure_results_preserve_targets_ports_and_statuses(self):
        for answer in (ipv4_answer(), ipv6_answer()):
            address = answer[4][0]
            for stdout, exit_code, nmap_status, sequence_status in (
                ("", 1, "error", "nmap_error"),
                ("<nmaprun/>", 1, "error", "nmap_error"),
                ("<nmaprun><host>", 0, "parse_error", "parse_error"),
                (" \n", 0, "no_output", "no_output"),
                ("<nmaprun/>", 0, "no_open_ports", "no_open_ports"),
            ):
                with self.subTest(address=address, stdout=stdout, exit_code=exit_code):
                    self.resolver.reset_mock()
                    self.resolver.side_effect = [[answer], AssertionError("Unexpected second DNS lookup")]
                    requests = []

                    def execute(request):
                        requests.append(request)
                        if request.program == "rustscan":
                            return CommandResult(request, f"{address} -> [80,443]\n", "", 0)
                        return CommandResult(request, stdout, "", exit_code)

                    with patch("netrunner.workflows.run_command", side_effect=execute):
                        result = run_port_scan("lab.example")

                    self.resolver.assert_called_once_with("lab.example", None, type=socket.SOCK_STREAM)
                    self.assertEqual([request.program for request in requests], ["rustscan", "nmap"])
                    self.assertEqual(requests[0].arguments[1], address)
                    expected = ["-sV", "-oX", "-"]
                    if answer[0] == socket.AF_INET6:
                        expected.append("-6")
                    self.assertEqual(requests[1].arguments, expected + ["-p", "80,443", address])
                    self.assertEqual(result.target, "lab.example")
                    self.assertEqual(result.rustscan.target, "lab.example")
                    self.assertEqual(result.rustscan.status, "success")
                    self.assertEqual(result.rustscan.open_ports, [80, 443])
                    self.assertEqual(result.nmap.target, "lab.example")
                    self.assertEqual(result.nmap.status, nmap_status)
                    self.assertEqual(result.nmap.ports, [])
                    self.assertEqual(result.status, sequence_status)
        self.process.assert_not_called()

    def test_cli_reports_invalid_target_without_launching_a_command(self):
        with (
            patch("sys.argv", ["nrc", "portscan", "192.0.2.0/24"]),
            patch.object(cli, "run_with_activity", side_effect=run_without_animation),
            patch("netrunner.workflows.run_command") as execute,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            with self.assertRaises(SystemExit) as error:
                cli.main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("not supported", stderr.getvalue())
        execute.assert_not_called()

    def test_prompted_cli_accepts_a_valid_single_target(self):
        with (
            patch("sys.argv", ["nrc", "portscan"]),
            patch.object(cli, "prompt_input", return_value="192.0.2.1") as prompt,
            patch.object(cli, "run_with_activity", side_effect=run_without_animation),
            patch("netrunner.workflows.run_command", side_effect=lambda request: CommandResult(request, "", "", 0)) as execute,
            patch.object(cli, "show_header"),
            patch.object(cli, "show_port_scan_result") as show_result,
        ):
            cli.main()
        prompt.assert_called_once_with("TARGET")
        self.assertEqual(execute.call_args.args[0].arguments[1], "192.0.2.1")
        self.assertEqual(show_result.call_args.args[0].status, "no_ports_discovered")

    def test_tui_invalid_input_returns_to_menu_and_cancel_is_preserved(self):
        for target in ("192.0.2.0/24", "0"):
            with self.subTest(target=target), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(interaction, "prompt", side_effect=["4", "0"]))
                stack.enter_context(patch.object(interaction, "prompt_input", return_value=target))
                stack.enter_context(patch.object(interaction, "run_with_activity", side_effect=run_without_animation))
                for name in ("clear_screen", "show_header", "show_networking_menu", "pause"):
                    stack.enter_context(patch.object(interaction, name))
                show_error = stack.enter_context(patch.object(interaction, "show_error"))
                execute = stack.enter_context(patch("netrunner.workflows.run_command"))
                interaction.run_networking_menu()
                execute.assert_not_called()
                self.assertEqual(show_error.call_count, int(target != "0"))

    def test_tui_valid_target_still_runs_and_displays_results(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(interaction, "prompt", side_effect=["4", "0"]))
            stack.enter_context(patch.object(interaction, "prompt_input", return_value="2001:db8::1"))
            stack.enter_context(patch.object(interaction, "run_with_activity", side_effect=run_without_animation))
            for name in ("clear_screen", "show_header", "show_networking_menu", "pause"):
                stack.enter_context(patch.object(interaction, name))
            show_error = stack.enter_context(patch.object(interaction, "show_error"))
            show_result = stack.enter_context(patch.object(interaction, "show_port_scan_result"))
            execute = stack.enter_context(patch(
                "netrunner.workflows.run_command",
                side_effect=lambda request: CommandResult(request, "", "", 0),
            ))
            interaction.run_networking_menu()
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args[0].arguments[1], "2001:db8::1")
        self.assertEqual(show_result.call_args.args[0].status, "no_ports_discovered")
        show_error.assert_not_called()
