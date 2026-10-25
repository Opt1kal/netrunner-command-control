import contextlib
import io
import unittest
from unittest.mock import patch

from netrunner import interaction, main as cli
from netrunner.core.models import CommandResult
from netrunner.tools.dns import InvalidDNSQuery, build_dns_request, parse_dns_result
from netrunner.workflows import run_dns


ANSWER = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
lab.example. 60 IN A 192.0.2.1

;; Query time: 4 msec
;; SERVER: 192.0.2.53#53(192.0.2.53) (UDP)
"""


def run_without_animation(subject, function, *args, **kwargs):
    return function(*args)


class DNSInputTests(unittest.TestCase):
    def setUp(self):
        # Unexpected execution or local name resolution must also stay offline.
        self.process = self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("Unexpected external command"))
        )
        self.resolver = self.enterContext(
            patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup"))
        )

    def test_names_are_explicit_queries_including_class_and_type_names(self):
        for query, expected in (
            ("lab.example", "lab.example"),
            ("LAB.Example.", "LAB.Example."),
            (".", "."),
            ("IN", "IN"),
            ("CH", "CH"),
            ("A", "A"),
            ("_sip._tcp.lab.example.", "_sip._tcp.lab.example."),
            ("*.lab.example", "*.lab.example"),
            ("bücher.example", "xn--bcher-kva.example"),
            ("bu\u0308cher.example.", "xn--bcher-kva.example."),
            ("lab\u3002example\uff61", "lab.example."),
            ("192.0.2.1", "192.0.2.1"),
            ("2001:db8::1", "2001:db8::1"),
        ):
            with self.subTest(query=query):
                request = build_dns_request(query, "a")
                self.assertEqual(request.program, "dig")
                self.assertEqual(request.arguments, ["-q", expected, "-t", "A"])
        self.process.assert_not_called()
        self.resolver.assert_not_called()

    def test_record_type_syntax_is_not_a_small_mnemonic_allowlist(self):
        for record_type in (
            "A", "aaaa", "MX", "CNAME", "NS", "SOA", "TXT", "SRV", "CAA",
            "NAPTR", "PTR", "DS", "DNSKEY", "RRSIG", "TLSA", "SSHFP",
            "HTTPS", "SVCB", "ANY", "NSAP-PTR", "AXFR", "IXFR=123",
            "TYPE0", "type65", "TYPE65535", "FUTURETYPE",
        ):
            with self.subTest(record_type=record_type):
                request = build_dns_request("lab.example", record_type)
                self.assertEqual(request.arguments, ["-q", "lab.example", "-t", record_type.upper()])
        self.process.assert_not_called()

    def test_directive_and_unsupported_query_inputs_never_execute(self):
        for query in (
            "", " ", " lab.example", "lab.example ",
            "@192.0.2.53", "+trace", "-f", "--help", "-x", "-q",
            "lab.example other.example", "lab.example\nother.example",
            "lab.example\t", "lab.example\x00", "lab.example\x7f",
            "lab.example,other.example", "/tmp/queries.txt", "./queries.txt",
            "lab\\032example", "lab..example", ".example", "lab.example..",
            "[2001:db8::1]", "fe80::1%eth0", "192.0.2.0/24",
            "\uff20server.example", "\uff0btrace", "\uff0df", "lab\ud800.example",
            "a" * 64 + ".example", ".".join(["a" * 63] * 4),
        ):
            with self.subTest(query=query), patch("netrunner.workflows.run_command") as execute:
                with self.assertRaises(InvalidDNSQuery):
                    run_dns(query, "A")
                execute.assert_not_called()
        self.process.assert_not_called()
        self.resolver.assert_not_called()

    def test_directive_and_unsupported_record_types_never_execute(self):
        for record_type in (
            "", " A", "A ", "A AAAA", "A\nAAAA", "A\x00", "A\x7f",
            "@192.0.2.53", "+trace", "-f", "--help", "-q", "-t",
            "other.example", "TYPE65536", "TYPE9999999999999999", "TYPE-1",
            "IXFR=-1", "IXFR=4294967296", "IXFR=1+trace", "\uff0btrace", "Ａ",
        ):
            with self.subTest(record_type=record_type), patch("netrunner.workflows.run_command") as execute:
                with self.assertRaises(InvalidDNSQuery):
                    run_dns("lab.example", record_type)
                execute.assert_not_called()
        self.process.assert_not_called()
        self.resolver.assert_not_called()

    def test_workflow_preserves_dns_result_metadata_and_answers(self):
        with patch(
            "netrunner.workflows.run_command",
            side_effect=lambda request: CommandResult(request, ANSWER, "", 0),
        ) as execute:
            request, result = run_dns("lab.example", "a")
        execute.assert_called_once_with(request)
        self.assertEqual(result.query, "lab.example")
        self.assertEqual(result.record_type, "A")
        self.assertEqual(result.answers, ["192.0.2.1"])
        self.assertEqual(result.query_time, 4)
        self.assertEqual(result.server, "192.0.2.53#53(192.0.2.53) (UDP)")
        self.assertEqual(result.status, "success")

    def test_parser_keeps_no_answer_and_dns_error_statuses(self):
        request = build_dns_request("lab.example", "A")
        for stdout, expected in (
            (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n", "not_answered"),
            (";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n", "not_found"),
            (";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n", "error"),
            ("", "error"),
        ):
            with self.subTest(expected=expected, stdout=stdout):
                result = parse_dns_result(CommandResult(request, stdout, "", 0))
                self.assertEqual(result.status, expected)
                self.assertEqual(result.answers, [])

    def test_failed_execution_never_accepts_partial_answers(self):
        request = build_dns_request("lab.example", "A")
        for exit_code in (1, 124, 126, 127):
            with self.subTest(exit_code=exit_code):
                result = parse_dns_result(CommandResult(request, ANSWER, "execution failed", exit_code))
                self.assertEqual(result.status, "error")
                self.assertEqual(result.answers, [])
                self.assertEqual(result.query, "lab.example")
                self.assertEqual(result.record_type, "A")

    def test_dns_and_recon_cli_report_validation_errors_before_execution(self):
        for arguments in (
            ["dns", "+trace", "A"],
            ["dns", "lab.example", "+trace"],
            ["dns", "--", "-f", "QUERIES.TXT"],
            ["recon", "+trace"],
        ):
            with (
                self.subTest(arguments=arguments),
                patch("sys.argv", ["nrc", *arguments]),
                patch.object(cli, "run_with_activity", side_effect=run_without_animation),
                patch("netrunner.workflows.run_command") as execute,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                with self.assertRaises(SystemExit) as error:
                    cli.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn("error:", stderr.getvalue())
                execute.assert_not_called()
        self.process.assert_not_called()

    def test_dns_and_recon_tui_report_validation_errors_and_return_to_menu(self):
        for selection, inputs in (
            ("2", ["+trace", "A"]),
            ("2", ["lab.example", "-f"]),
            ("11", ["+trace"]),
        ):
            with (
                self.subTest(selection=selection, inputs=inputs),
                patch.object(interaction, "prompt", side_effect=[selection, "0"]),
                patch.object(interaction, "prompt_input", side_effect=inputs),
                patch.object(interaction, "run_with_activity", side_effect=run_without_animation),
                patch.object(interaction, "clear_screen"),
                patch.object(interaction, "show_header"),
                patch.object(interaction, "show_networking_menu"),
                patch.object(interaction, "show_error") as error,
                patch.object(interaction, "pause") as pause,
                patch("netrunner.workflows.run_command") as execute,
            ):
                interaction.run_networking_menu()
                error.assert_called_once()
                pause.assert_called_once()
                execute.assert_not_called()
        self.process.assert_not_called()

    def test_dns_tui_back_choice_remains_side_effect_free(self):
        with (
            patch.object(interaction, "prompt", side_effect=["2", "0"]),
            patch.object(interaction, "prompt_input", return_value="0"),
            patch.object(interaction, "clear_screen"),
            patch.object(interaction, "show_header"),
            patch.object(interaction, "show_networking_menu"),
            patch.object(interaction, "show_error") as error,
            patch("netrunner.workflows.run_command") as execute,
        ):
            interaction.run_networking_menu()
        error.assert_not_called()
        execute.assert_not_called()
        self.process.assert_not_called()
