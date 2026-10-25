from dataclasses import dataclass
from ..core.models import CommandRequest, CommandResult

def build_route_request(target: str) -> CommandRequest:
    return CommandRequest(
        program="traceroute",
        arguments=["-4", target],
        description=f"Trace IPv4 route to {target}",
    )

@dataclass
class RouteHop:
    hop_number: int
    probes: list[RouteProbe]

@dataclass
class RouteTraceResult:
    target: str
    destination_ip: str | None
    hops: list[RouteHop]
    responding_hops: int
    destination_reached: bool
    status: str

@dataclass
class RouteProbe:
    hostname: str | None
    ip: str | None
    response_time: float | None

def parse_route_result(result: CommandResult) -> RouteTraceResult:
    lines = result.stdout.splitlines()
    hops: list[RouteHop] = []
    if result.exit_code != 0 or not lines:
        return RouteTraceResult(
            target=result.request.arguments[1],
            destination_ip=None,
            hops=hops,
            responding_hops=0,
            destination_reached=False,
            status="failed",
        )
    header = lines[0]
    start = header.find("(")
    end = header.find(")")
    destination_ip = header[start + 1:end]

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if not line[0].isdigit():
            continue

        parts = line.split()
        hop_number = int(parts[0])
        probes: list[RouteProbe] = []

        index = 1

        while index < len(parts):
            if parts[index] == "*":
                probes.append(
                    RouteProbe(
                        hostname=None,
                        ip=None,
                        response_time=None,
                    )
                )
                index += 1
            else:
                try:
                    response_time = float(parts[index])
                    probes.append(
                        RouteProbe(
                            hostname=hostname,
                            ip=ip,
                            response_time=response_time,
                            )
                        )
                    index += 2
                except ValueError:
                    hostname = parts[index]
                    ip = parts[index + 1].strip("()")
                    response_time = float(parts[index + 2])
                    probes.append(
                        RouteProbe(
                            hostname=hostname,
                            ip=ip,
                            response_time=response_time,
                            )
                        )
                    index += 4
        hops.append(
            RouteHop(
                hop_number=hop_number,
                probes=probes,
            )
        )
    target = result.request.arguments[-1]
    responding_hops = 0
    destination_reached = False

    for hop in hops:
        hop_responded = False

        for probe in hop.probes:
            if probe.ip == destination_ip:
                destination_reached = True

            if probe.response_time is not None:
                hop_responded = True

        if hop_responded:
            responding_hops += 1

    if responding_hops == 0:
        status = "failed"
    elif destination_reached:
        status = "success"
    else:
        status = "partial_success"

    return RouteTraceResult(
        target=target,
        destination_ip=destination_ip,
        hops=hops,
        responding_hops=responding_hops,
        destination_reached=destination_reached,
        status=status,
        )
