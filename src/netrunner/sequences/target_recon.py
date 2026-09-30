from dataclasses import dataclass
from ..tools.dns import DNSResult
from ..tools.ping import PingResult
from ..tools.route import RouteTraceResult
from ..workflows import run_dns, run_ping, run_route


@dataclass
class TargetReconResult:
    target: str
    dns_result: DNSResult
    ping_result: PingResult
    route_result: RouteTraceResult


def run_target_recon(target: str) -> TargetReconResult:
    _, dns_result = run_dns(target, "A")
    _, ping_result = run_ping(target)
    _, route_result = run_route(target)

    return TargetReconResult(
        target=target,
        dns_result=dns_result,
        ping_result=ping_result,
        route_result=route_result,
    )
