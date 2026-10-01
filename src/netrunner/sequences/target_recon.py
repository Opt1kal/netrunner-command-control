from dataclasses import dataclass

from rich.diagnose import report
from ..tools.dns import DNSResult
from ..tools.ping import PingResult
from ..tools.route import RouteTraceResult
from ..workflows import run_dns, run_ping, run_route
from collections.abc import Callable


@dataclass
class TargetReconResult:
    target: str
    dns_result: DNSResult
    ping_result: PingResult
    route_result: RouteTraceResult


def run_target_recon(
    target: str,
    progress: Callable[[str, str], None] | None = None,
) -> TargetReconResult:
    def report(step: str, status: str):
        if progress is not None:
            progress(step, status)

    report("dns", "running")
    _, dns_result = run_dns(target, "A")
    report("dns", "complete")

    report("ping", "running")
    _, ping_result = run_ping(target)
    report("ping", "complete")

    report("route", "running")
    _, route_result = run_route(target)
    report("route", "complete")

    return TargetReconResult(
        target=target,
        dns_result=dns_result,
        ping_result=ping_result,
        route_result=route_result,
    )
