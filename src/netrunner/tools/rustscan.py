from dataclasses import dataclass
from ..core.models import CommandRequest, CommandResult

@dataclass
class RustScanResult:
    target: str
    open_ports: list[int]
    status: str

def build_rustscan_request(target: str) -> CommandRequest:
    return CommandRequest(
        program="rustscan",
        arguments=["-a", target, "--top", "--greppable", "--no-banner"],
        description=f"Perform a RustScan port scan on {target}.",
    )

def parse_rustscan_result(result: CommandResult) -> RustScanResult:
    target = result.request.arguments[1]

    if result.exit_code != 0:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    output = result.stdout.strip()

    if not output:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="no_ports_discovered",
        )

    if "->" not in output:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    _, ports_text = output.split("->", 1)
    ports_strings = ports_text.strip("[]").split(",")
    open_ports: list[int] = [int(port.strip()) for port in ports_strings if port.strip().isdigit()]

    return RustScanResult(
        target=target,
        open_ports=open_ports,
        status="success",
    )
