import unittest

from netrunner.core.models import CommandRequest, CommandResult
from netrunner.tools.rustscan import parse_rustscan_result


class RustScanParserTests(unittest.TestCase):
    def parse(self, stdout, exit_code=0, target="192.0.2.1"):
        return parse_rustscan_result(
            CommandResult(
                request=CommandRequest("rustscan", ["-a", target], "Parser fixture"),
                stdout=stdout,
                stderr="",
                exit_code=exit_code,
            )
        )

    def test_single_port_is_retained(self):
        result = self.parse("192.0.2.1 -> [80]\n")
        self.assertEqual(result.open_ports, [80])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.target, "192.0.2.1")

    def test_multiple_ports_keep_order(self):
        for ports in ([80, 443], [443, 22, 80], [1, 65535]):
            with self.subTest(ports=ports):
                output = f"192.0.2.1 -> [{','.join(map(str, ports))}]\n"
                result = self.parse(output)
                self.assertEqual(result.open_ports, ports)
                self.assertEqual(result.status, "success")

    def test_whitespace_and_compact_output(self):
        for target, output in (
            ("192.0.2.1", "192.0.2.1->[80,443]"),
            ("192.0.2.1", " \t192.0.2.1 -> [ 80, 443 ]\r\n"),
            ("2001:db8::1", "2001:db8::1\t->\t[80,\t443]\n"),
        ):
            with self.subTest(output=output):
                result = self.parse(output, target=target)
                self.assertEqual(result.open_ports, [80, 443])
                self.assertEqual(result.status, "success")

    def test_mismatched_addresses_are_errors(self):
        for target, reported in (
            ("192.0.2.1", "192.0.2.2"),
            ("2001:db8::1", "2001:db8::2"),
            ("192.0.2.1", "2001:db8::1"),
        ):
            for ports in ("80,443", ""):
                with self.subTest(target=target, reported=reported, ports=ports):
                    result = self.parse(f"{reported} -> [{ports}]", target=target)
                    self.assertEqual(result.status, "error")
                    self.assertEqual(result.open_ports, [])
                    self.assertEqual(result.target, target)

    def test_equivalent_ipv6_addresses_match(self):
        for target, reported in (
            ("2001:db8::1", "2001:0DB8:0:0:0:0:0:1"),
            ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ):
            with self.subTest(target=target, reported=reported):
                result = self.parse(f"{reported} -> [80,443]", target=target)
                self.assertEqual(result.status, "success")
                self.assertEqual(result.open_ports, [80, 443])
                self.assertEqual(result.target, target)

    def test_invalid_addresses_are_errors(self):
        for target, reported in (
            ("192.0.2.1", "not-an-ip"),
            ("192.0.2.1", "lab.example"),
            ("192.0.2.1", "999.0.0.1"),
            ("2001:db8::1", "2001:db8::zz"),
            ("not-an-ip", "192.0.2.1"),
            ("not-an-ip", "not-an-ip"),
        ):
            with self.subTest(target=target, reported=reported):
                result = self.parse(f"{reported} -> [80,443]", target=target)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.open_ports, [])

    def test_empty_output_or_list_means_no_ports_discovered(self):
        for output in ("", " \t\r\n", "192.0.2.1 -> []", "192.0.2.1 -> [ \t ]"):
            with self.subTest(output=output):
                result = self.parse(output)
                self.assertEqual(result.open_ports, [])
                self.assertEqual(result.status, "no_ports_discovered")

    def test_nonzero_exit_is_error_even_with_valid_ports(self):
        for output in ("", "192.0.2.1 -> [80,443]"):
            with self.subTest(output=output):
                result = self.parse(output, exit_code=1)
                self.assertEqual(result.open_ports, [])
                self.assertEqual(result.status, "error")

    def test_malformed_records_are_errors(self):
        for output in (
            "unexpected output",
            "192.0.2.1 [80,443]",
            "-> [80]",
            "192.0.2.1 -> 80,443",
            "192.0.2.1 -> [80,443",
            "192.0.2.1 -> 80,443]",
            "192.0.2.1 -> [[80,443]]",
            "192.0.2.1 -> [80,443] trailing text",
            "192.0.2.1 -> [80]\n192.0.2.2 -> [443]",
            "192.0.2.1->[80]192.0.2.2->[443]",
            "192.0.2.1->garbage->[443]",
        ):
            with self.subTest(output=output):
                result = self.parse(output)
                self.assertEqual(result.open_ports, [])
                self.assertEqual(result.status, "error")

    def test_invalid_port_tokens_do_not_return_partial_success(self):
        for ports in (
            "80,bogus,443",
            ",80",
            "80,",
            "80,,443",
            "80 443",
            "80,-1",
            "80,+443",
            "80,0",
            "80,65536",
            "80,4_43",
            "80,\u00b2",
            "80,\uff14\uff14\uff13",
        ):
            with self.subTest(ports=ports):
                result = self.parse(f"192.0.2.1 -> [{ports}]")
                self.assertEqual(result.open_ports, [])
                self.assertEqual(result.status, "error")
