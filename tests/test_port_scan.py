import unittest
from types import SimpleNamespace
from unittest.mock import patch

from netrunner.core.models import CommandResult
from netrunner.sequences.port_scan import run_port_scan
from netrunner.tools.rustscan import build_rustscan_request


class PortScanParserIntegrationTests(unittest.TestCase):
    def test_discovered_ports_reach_nmap(self):
        for ports in ([80], [80, 443]):
            with self.subTest(ports=ports):
                result, nmap = self.run_with_output(
                    f"192.0.2.1 -> [{','.join(map(str, ports))}]\n"
                )
                self.assertEqual(result.rustscan.open_ports, ports)
                self.assertEqual(result.status, "success")
                nmap.assert_called_once_with("lab.example", ports=ports)

    def test_empty_or_malformed_discovery_skips_nmap(self):
        for output, status in (
            ("", "no_ports_discovered"),
            ("192.0.2.1 -> []", "no_ports_discovered"),
            ("192.0.2.1 -> [80,bogus]", "rustscan_error"),
        ):
            with self.subTest(output=output):
                result, nmap = self.run_with_output(output)
                nmap.assert_not_called()
                self.assertIsNone(result.nmap)
                self.assertEqual(result.status, status)

    def run_with_output(self, stdout):
        command_result = CommandResult(
            request=build_rustscan_request("lab.example"),
            stdout=stdout,
            stderr="",
            exit_code=0,
        )
        with (
            patch("subprocess.run", side_effect=AssertionError("Unexpected external command")),
            patch("netrunner.workflows.run_command", return_value=command_result),
            patch(
                "netrunner.sequences.port_scan.run_nmap",
                return_value=(None, SimpleNamespace(status="success")),
            ) as nmap,
        ):
            result = run_port_scan("lab.example")
        return result, nmap
