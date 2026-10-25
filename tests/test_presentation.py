import io
import unittest
from unittest.mock import patch

from rich.console import Console

from netrunner.core.models import CommandRequest
from netrunner.presentation import activity, console as presentation
from netrunner.presentation.runtime import netrunner_theme
from netrunner.sequences.port_scan import PortScanResult
from netrunner.sequences.target_recon import TargetReconResult
from netrunner.tools.dns import DNSResult
from netrunner.tools.nmap import NmapPort, NmapResult
from netrunner.tools.ping import PingResult
from netrunner.tools.route import RouteHop, RouteProbe, RouteTraceResult
from netrunner.tools.rustscan import RustScanResult


PAYLOADS = ("[/red]", "[italic red]value[/italic red]", "[80,443] [::1]", ":warning:")


class PresentationTests(unittest.TestCase):
    def setUp(self):
        # Rendering fixtures never need DNS or an external command.
        self.enterContext(patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup")))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("Unexpected external command")))

    def render(self, function, *args, width=240, **kwargs):
        output = io.StringIO()
        console = Console(file=output, width=width, theme=netrunner_theme, color_system=None)
        with (
            patch.object(presentation, "console", console),
            patch.object(console, "print", wraps=console.print) as printed,
        ):
            function(*args, **kwargs)
        segments = [
            segment
            for call in printed.call_args_list
            for segment in console.render(call.args[0])
        ]
        return output.getvalue(), segments

    def assert_literal(self, output, segments, *values):
        for value in values:
            self.assertIn(value, output)
        # Balanced payload markup must not add its italic/red formatting.
        for segment in segments:
            if "[italic red]" in segment.text:
                self.assertFalse(segment.style and segment.style.italic)

    def ping_result(self, target):
        return PingResult(target, "192.0.2.1", 1, 1, 0.0, 1.0, 1.0, 1.0, "success", 1)

    def route_result(self, target):
        return RouteTraceResult(target, "192.0.2.1", [], 0, False, "failed")

    def nmap_result(self, payload, status="success"):
        return NmapResult(
            target="target-" + payload,
            resolved_ip="address-" + payload,
            hostname="hostname-" + payload,
            host_state="up",
            ports=[NmapPort(80, "protocol-" + payload, "state-" + payload,
                            "service-" + payload, "product-" + payload, "version-" + payload)],
            scanned_ports=1,
            elapsed=0.1,
            status=status,
        )

    def test_dns_fields_render_literally_and_keep_application_styling(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                result = DNSResult("query-" + payload, "type-" + payload,
                                   ["answer-" + payload], 1, "server-" + payload, "success")
                output, segments = self.render(presentation.show_dns_result, result)
                self.assert_literal(output, segments, result.query, result.record_type,
                                    result.answers[0], result.server)
                query_segments = [segment for segment in segments if result.query in segment.text]
                self.assertTrue(query_segments)
                expected = netrunner_theme.styles["nr.success"]
                self.assertTrue(all(segment.style.bold and segment.style.color == expected.color
                                    for segment in query_segments))

    def test_nmap_fields_render_literally_in_both_result_views(self):
        for payload in PAYLOADS:
            nmap = self.nmap_result(payload)
            scan = PortScanResult(nmap.target, RustScanResult(nmap.target, [80], "success"),
                                  nmap, "success")
            for function, result in ((presentation.show_nmap_result, nmap),
                                     (presentation.show_port_scan_result, scan)):
                with self.subTest(payload=payload, view=function.__name__):
                    output, segments = self.render(function, result, width=400)
                    port = nmap.ports[0]
                    self.assert_literal(output, segments, nmap.target, port.protocol, port.state,
                                        port.service, port.product, port.version)
                    if function is presentation.show_nmap_result:
                        self.assert_literal(output, segments, nmap.resolved_ip, nmap.hostname)

    def test_route_hostnames_and_addresses_render_literally_for_both_hop_layouts(self):
        for payload in PAYLOADS:
            for multiple_routers in (False, True):
                with self.subTest(payload=payload, multiple_routers=multiple_routers):
                    result = self.route_result("target-" + payload)
                    result.destination_ip = "destination-" + payload
                    probes = [RouteProbe("router-" + payload, "address-" + payload, 1.0)]
                    if multiple_routers:
                        probes.append(RouteProbe("other-" + payload, "192.0.2.2", 2.0))
                    result.hops = [RouteHop(1, probes)]
                    output, segments = self.render(presentation.show_route_result, result, verbose=True)
                    self.assert_literal(output, segments, result.target, result.destination_ip,
                                        probes[0].hostname, probes[0].ip)
                    if multiple_routers:
                        self.assert_literal(output, segments, probes[1].hostname)

    def test_ping_rustscan_and_recon_targets_render_literally(self):
        for payload in PAYLOADS:
            ping = self.ping_result(payload)
            ping.resolved_ip = "resolved-" + payload
            rustscan = RustScanResult(payload, [80], "success")
            dns = DNSResult("lab.example", "A", ["answer-" + payload], 1, None, "success")
            recon = TargetReconResult(payload, dns, ping, self.route_result(payload))
            for function, result in ((presentation.show_ping_result, ping),
                                     (presentation.show_rustscan_result, rustscan),
                                     (presentation.show_recon_result, recon)):
                with self.subTest(payload=payload, view=function.__name__):
                    output, segments = self.render(function, result)
                    self.assert_literal(output, segments, payload)
                    if function is presentation.show_ping_result:
                        self.assert_literal(output, segments, ping.resolved_ip)
                    if function is presentation.show_recon_result:
                        self.assert_literal(output, segments, dns.answers[0])

    def test_requests_errors_and_prompts_preserve_literal_values(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                request = CommandRequest("program-" + payload, ["argument-" + payload],
                                         "description-" + payload)
                output, _ = self.render(presentation.show_request, request)
                for value in (request.program, request.arguments[0], request.description):
                    self.assertIn(value, output)
                output, segments = self.render(presentation.show_error, payload)
                self.assert_literal(output, segments, payload)
                with patch("builtins.input", return_value="entered"):
                    output, _ = self.render(presentation.prompt, payload)
                    self.assertIn(payload, output)
                    output, _ = self.render(presentation.prompt_input, payload, default=payload)
                    self.assertIn(f"{payload} [{payload}]", output)

    def test_activity_subject_and_unknown_status_render_literally(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload), patch.object(activity, "Live") as live:
                progress = activity.ExecutionActivity(payload)
                progress.update({"dns": payload, "ping": "waiting", "route": "complete"})
                panel = live.return_value.update.call_args.args[0]
                output, segments = self.render(lambda: presentation.console.print(panel))
                self.assert_literal(output, segments, payload, payload.upper())

    def test_tool_failure_status_uses_error_styling(self):
        for function, result in (
            (presentation.show_rustscan_result, RustScanResult("192.0.2.1", [], "error")),
            (presentation.show_nmap_result, self.nmap_result("lab.example", status="error")),
        ):
            with self.subTest(view=function.__name__):
                _, segments = self.render(function, result)
                errors = [segment for segment in segments if "ERROR" in segment.text]
                self.assertTrue(errors)
                expected = netrunner_theme.styles["nr.error"]
                self.assertTrue(all(segment.style.bold and segment.style.color == expected.color
                                    for segment in errors))

    def test_main_menu_only_advertises_implemented_choices_at_both_widths(self):
        for width in (40, 100):
            with self.subTest(width=width):
                output, _ = self.render(presentation.show_main_menu, width=width)
                self.assertIn("[01] NETWORKING TOOLS", output)
                self.assertIn("[00] EXIT", output)
                for unavailable in ("[02]", "[03]", "[04]", "[05]", "[06]"):
                    self.assertNotIn(unavailable, output)
