from dataclasses import dataclass
import re
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

    # Accept one complete greppable record; never return a partial port list.
    match = re.fullmatch(r"[^\s<>\[\]]+[ \t]*->[ \t]*\[([0-9, \t]*)\]", output)
    if match is None:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    ports_text = match.group(1).strip()
    if not ports_text:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="no_ports_discovered",
        )

    try:
        open_ports = [int(port.strip()) for port in ports_text.split(",")]
    except ValueError:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    if any(port < 1 or port > 65535 for port in open_ports):
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    return RustScanResult(
        target=target,
        open_ports=open_ports,
        status="success",
    )
