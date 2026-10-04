from dataclasses import dataclass
from ..core.models import CommandRequest, CommandResult
import xml.etree.ElementTree as ET


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None

@dataclass
class NmapResult:
    target: str
    resolved_ip: str | None
    hostname: str | None
    host_state: str | None
    ports: list[NmapPort]
    scanned_ports: int
    elapsed: float | None
    status: str

def build_nmap_request(
    target: str,
    ports: list[int] | None = None,
) -> CommandRequest:
    arguments = ["-sV", "-oX", "-"]

    if ports:
        ports_str = ",".join(str(port) for port in ports)
        arguments.extend(["-p", ports_str])

    arguments.append(target)

    return CommandRequest(
        program="nmap",
        arguments=arguments,
        description=f"Perform a Nmap service scan on {target}.",
    )

def parse_nmap_result(result: CommandResult) -> NmapResult:
    target = result.request.arguments[-1]

    if result.exit_code != 0:
        return NmapResult(
            target=target,
            resolved_ip=None,
            hostname=None,
            host_state=None,
            ports=[],
            scanned_ports=0,
            elapsed=None,
            status="error",
        )

    output = result.stdout.strip()

    if not output:
        return NmapResult(
            target=target,
            resolved_ip=None,
            hostname=None,
            host_state=None,
            ports=[],
            scanned_ports=0,
            elapsed=None,
            status="no_output",
        )

    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return NmapResult(
            target=target,
            resolved_ip=None,
            hostname=None,
            host_state=None,
            ports=[],
            scanned_ports=0,
            elapsed=None,
            status="parse_error",
        )

    resolved_ip = None
    hostname = None
    host_state = None
    ports = []
    status = "success"

    scaninfo = root.find("scaninfo")
    if scaninfo is not None:
        scanned_ports = int(scaninfo.get("numservices", 0))
    else:
        scanned_ports = 0

    finished = root.find("runstats/finished")
    if finished is not None:
        elapsed_attr = finished.get("elapsed")
        elapsed = float(elapsed_attr) if elapsed_attr is not None else None
    else:
        elapsed = None

    for host in root.findall("host"):
        address_elem = host.find('address[@addrtype="ipv4"]')
        if address_elem is not None:
            resolved_ip = address_elem.get("addr")

        hostname_elem = host.find("hostnames/hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name")

        status_elem = host.find("status")
        if status_elem is not None:
            host_state = status_elem.get("state")

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_id = port.get("portid")
                if port_id is None:
                    continue

                port_number = int(port_id)
                protocol = port.get("protocol") or "unknown"

                state_elem = port.find("state")
                service_elem = port.find("service")

                state = (
                    state_elem.get("state")
                    if state_elem is not None
                    else "unknown"
                )

                service = (
                    service_elem.get("name")
                    if service_elem is not None
                    else None
                )

                product = (
                    service_elem.get("product")
                    if service_elem is not None
                    else None
                )

                version = (
                    service_elem.get("version")
                    if service_elem is not None
                    else None
                )

                if state == "open":
                    ports.append(
                        NmapPort(
                            port=port_number,
                            protocol=protocol,
                            state=state,
                            service=service,
                            product=product,
                            version=version,
                        )
                    )

    if not ports:
        status = "no_open_ports"

    return NmapResult(
        target=target,
        resolved_ip=resolved_ip,
        hostname=hostname,
        host_state=host_state,
        ports=ports,
        scanned_ports=scanned_ports,
        elapsed=elapsed,
        status=status,
    )
