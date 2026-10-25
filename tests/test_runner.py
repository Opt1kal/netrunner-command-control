import contextlib
import errno
import subprocess
import unittest
from unittest.mock import patch

from netrunner import interaction, main as cli
from netrunner.core.models import CommandRequest
from netrunner.core.runner import run_command
from netrunner.sequences.port_scan import run_port_scan
from netrunner.tools.dns import build_dns_request
from netrunner.tools.nmap import build_nmap_request
from netrunner.tools.ping import build_ping_request
from netrunner.tools.route import build_route_request
from netrunner.tools.rustscan import build_rustscan_request
from netrunner.workflows import run_dns, run_nmap, run_ping, run_route, run_rustscan


PING_OUTPUT = (
    "PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.\n"
    "5 packets transmitted, 5 received, 0% packet loss, time 4000ms\n"
    "rtt min/avg/max/mdev = 1.000/2.000/3.000/0.100 ms\n"
)
DNS_OUTPUT = (
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
    ";; ANSWER SECTION:\n"
    "example.test. 60 IN A 192.0.2.1\n\n"
)
ROUTE_OUTPUT = (
    "traceroute to 192.0.2.1 (192.0.2.1), 30 hops max, 60 byte packets\n"
    " 1 lab.example (192.0.2.1) 1.000 ms 1.100 ms 1.200 ms\n"
)
RUSTSCAN_OUTPUT = "192.0.2.1 -> [80,443]\n"
NMAP_OUTPUT = (
    '<nmaprun><host><status state="up"/>'
    '<address addr="192.0.2.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80">'
    '<state state="open"/></port></ports></host></nmaprun>'
)


def without_animation(subject, function, *args, **kwargs):
    return function(*args, **kwargs)


class CommandExecutionTests(unittest.TestCase):
    def setUp(self):
        # Guard every path, including mistakes in failure handling, from networking.
        self.process = self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("Unexpected external command"))
        )
        self.enterContext(
            patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup"))
        )

    def test_missing_and_inaccessible_tools_return_command_failures(self):
        request = build_rustscan_request("192.0.2.1")
        for error, exit_code in (
            (FileNotFoundError("missing executable"), 127),
            (PermissionError("permission denied"), 126),
            (OSError(errno.ENOEXEC, "invalid executable format"), 126),
        ):
            with self.subTest(error=type(error).__name__):
                self.process.side_effect = error
                result = run_command(request)
                self.assertIs(result.request, request)
                self.assertEqual(result.exit_code, exit_code)
                self.assertEqual(result.stdout, "")
                self.assertIn("rustscan", result.stderr)
                self.assertTrue(result.stderr)

    def test_timeout_preserves_text_output_and_reports_failure(self):
        request = build_rustscan_request("192.0.2.1")
        for stdout, stderr in (
            (b"192.0.2.1 -> [80]\n", b"partial diagnostic\n"),
            ("192.0.2.1 -> [80]\n", "partial diagnostic\n"),
            (None, None),
        ):
            with self.subTest(stdout=stdout):
                self.process.side_effect = subprocess.TimeoutExpired(
                    "rustscan", 900, output=stdout, stderr=stderr
                )
                result = run_command(request)
                self.assertIs(result.request, request)
                self.assertEqual(result.exit_code, 124)
                self.assertIsInstance(result.stdout, str)
                self.assertIsInstance(result.stderr, str)
                self.assertEqual(result.stdout, "192.0.2.1 -> [80]\n" if stdout else "")
                self.assertIn("900-second execution deadline", result.stderr)
                if stderr:
                    self.assertIn("partial diagnostic", result.stderr)

    def test_current_tools_have_distinct_deadlines_and_results_are_preserved(self):
        requests = (
            (build_ping_request("192.0.2.1", 5), 60),
            (build_dns_request("example.test", "A"), 60),
            (build_route_request("192.0.2.1"), 600),
            (build_rustscan_request("192.0.2.1"), 900),
            (build_nmap_request("192.0.2.1", [80]), 1800),
            (CommandRequest("other-tool", [], "Generic runner request"), None),
        )
        for request, timeout in requests:
            with self.subTest(program=request.program):
                self.process.reset_mock()
                self.process.side_effect = None
                self.process.return_value = subprocess.CompletedProcess(
                    [], 3, stdout="tool output", stderr="tool diagnostic"
                )
                result = run_command(request)
                self.process.assert_called_once_with(
                    [request.program, *request.arguments],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                self.assertIs(result.request, request)
                self.assertEqual((result.stdout, result.stderr, result.exit_code),
                                 ("tool output", "tool diagnostic", 3))

    def test_missing_and_inaccessible_tools_fail_through_real_workflows(self):
        for workflow, args, status in (
            (run_ping, ("192.0.2.1",), "error"),
            (run_dns, ("example.test", "A"), "error"),
            (run_route, ("192.0.2.1",), "failed"),
            (run_rustscan, ("192.0.2.1",), "error"),
            (run_nmap, ("192.0.2.1", [80]), "error"),
        ):
            for error in (FileNotFoundError("missing"), PermissionError("denied")):
                with self.subTest(workflow=workflow.__name__, error=type(error).__name__):
                    self.process.side_effect = error
                    _, result = workflow(*args)
                    self.assertEqual(result.status, status)

    def test_timeout_cannot_turn_partial_output_into_success(self):
        for workflow, args, output, status in (
            (run_ping, ("192.0.2.1",), PING_OUTPUT, "error"),
            (run_dns, ("example.test", "A"), DNS_OUTPUT, "error"),
            (run_route, ("192.0.2.1",), ROUTE_OUTPUT, "failed"),
            (run_rustscan, ("192.0.2.1",), RUSTSCAN_OUTPUT, "error"),
            (run_nmap, ("192.0.2.1", [80]), NMAP_OUTPUT, "error"),
        ):
            with self.subTest(workflow=workflow.__name__):
                self.process.side_effect = subprocess.TimeoutExpired(
                    "mocked tool", 1, output=output.encode()
                )
                _, result = workflow(*args)
                self.assertEqual(result.status, status)

    def test_rustscan_execution_failures_skip_dependent_nmap(self):
        for error in (
            FileNotFoundError("missing"),
            PermissionError("denied"),
            subprocess.TimeoutExpired("rustscan", 900, output=RUSTSCAN_OUTPUT.encode()),
        ):
            with self.subTest(error=type(error).__name__):
                self.process.reset_mock()
                self.process.side_effect = error
                result = run_port_scan("192.0.2.1")
                self.process.assert_called_once()
                self.assertEqual(self.process.call_args.args[0][0], "rustscan")
                self.assertEqual(result.status, "rustscan_error")
                self.assertEqual(result.rustscan.status, "error")
                self.assertEqual(result.rustscan.open_ports, [])
                self.assertIsNone(result.nmap)

    def test_nmap_execution_failures_remain_sequence_errors(self):
        for error in (
            FileNotFoundError("missing"),
            PermissionError("denied"),
            subprocess.TimeoutExpired("nmap", 1800, output=NMAP_OUTPUT.encode()),
        ):
            with self.subTest(error=type(error).__name__):
                self.process.reset_mock()
                self.process.side_effect = [
                    subprocess.CompletedProcess([], 0, stdout=RUSTSCAN_OUTPUT, stderr=""),
                    error,
                ]
                result = run_port_scan("192.0.2.1")
                self.assertEqual(
                    [call.args[0][0] for call in self.process.call_args_list],
                    ["rustscan", "nmap"],
                )
                self.assertEqual(result.status, "nmap_error")
                self.assertEqual(result.rustscan.open_ports, [80, 443])
                self.assertEqual(result.nmap.status, "error")
                self.assertEqual(result.nmap.ports, [])

    def test_ping_no_reply_and_success_semantics_are_preserved(self):
        for exit_code, output, status in (
            (0, PING_OUTPUT, "success"),
            (1, "5 packets transmitted, 0 received, 100% packet loss, time 4000ms\n", "no_response"),
            (1, "5 packets transmitted, 3 received, 40% packet loss, time 4000ms\n", "unstable"),
            (2, PING_OUTPUT, "error"),
        ):
            with self.subTest(exit_code=exit_code, status=status):
                self.process.side_effect = None
                self.process.return_value = subprocess.CompletedProcess(
                    [], exit_code, stdout=output, stderr=""
                )
                _, result = run_ping("192.0.2.1")
                self.assertEqual(result.status, status)
                self.assertEqual(result.count, 5)

    def test_cli_displays_missing_tool_as_failed_scan(self):
        self.process.side_effect = FileNotFoundError("missing")
        with (
            patch("sys.argv", ["nrc", "portscan", "192.0.2.1"]),
            patch.object(cli, "run_with_activity", side_effect=without_animation),
            patch.object(cli, "show_header"),
            patch.object(cli, "show_port_scan_result") as display,
        ):
            cli.main()
        self.assertEqual(display.call_args.args[0].status, "rustscan_error")
        self.process.assert_called_once()

    def test_tui_displays_inaccessible_tool_as_failed_scan_and_returns(self):
        self.process.side_effect = PermissionError("denied")
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(interaction, "prompt", side_effect=["4", "0"]))
            stack.enter_context(patch.object(interaction, "prompt_input", return_value="192.0.2.1"))
            stack.enter_context(patch.object(interaction, "run_with_activity", side_effect=without_animation))
            for name in ("clear_screen", "show_header", "show_networking_menu", "pause"):
                stack.enter_context(patch.object(interaction, name))
            display = stack.enter_context(patch.object(interaction, "show_port_scan_result"))
            interaction.run_networking_menu()
        self.assertEqual(display.call_args.args[0].status, "rustscan_error")
        self.process.assert_called_once()
