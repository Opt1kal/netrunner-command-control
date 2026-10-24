from dataclasses import dataclass
from ipaddress import ip_address
import re
import socket
from ..core.models import CommandRequest, CommandResult


class InvalidPortScanTarget(ValueError):
    """The requested target cannot safely identify one scan address."""


def resolve_single_target(target: str) -> str:
    """Validate one IP/hostname and pin it to one IP before invoking RustScan.

    RustScan can interpret unresolved names as files and expand DNS results.
    Passing a numeric address avoids both behaviors without reading local files.
    """
    if not target or any(character.isspace() for character in target):
        raise InvalidPortScanTarget("Enter one IPv4 address, IPv6 address, or DNS hostname.")

    # Scope IDs and bracket/port notation are not supported by RustScan's IpAddr.
    if any(character in target for character in "/\\,%[]@"):
        raise InvalidPortScanTarget("Ranges, lists, files, options, and scoped addresses are not supported.")

    try:
        return str(ip_address(target))
    except ValueError:
        pass

    try:
        hostname = target.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidPortScanTarget("Enter a valid DNS hostname or IP address.") from exc

    # Permit single-label names, IDNs, and a trailing root dot, without requiring
    # public suffixes or a particular TLD. Numeric-only malformed IPs are errors.
    name = hostname.removesuffix(".")
    labels = name.split(".")
    if (
        len(name) > 253
        or re.fullmatch(r"[0-9.]+", name)
        or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        )
    ):
        raise InvalidPortScanTarget("Enter a valid DNS hostname or IP address; target expansion is not supported.")

    try:
        addresses = set()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = ip_address(sockaddr[0])
            if getattr(address, "scope_id", None) or (family == socket.AF_INET6 and sockaddr[3]):
                raise InvalidPortScanTarget("Scoped IPv6 addresses are not supported.")
            addresses.add(str(address))
    except (OSError, ValueError) as exc:
        raise InvalidPortScanTarget("The hostname could not be resolved. Enter a resolvable hostname or IP address.") from exc

    if len(addresses) != 1:
        raise InvalidPortScanTarget("The hostname must resolve to exactly one address. Enter a specific IP address.")
    return addresses.pop()


@dataclass
class RustScanResult:
    target: str
    open_ports: list[int]
    status: str

def build_rustscan_request(target: str) -> CommandRequest:
    address = resolve_single_target(target)
    return CommandRequest(
        program="rustscan",
        arguments=["-a", address, "--top", "--greppable", "--no-banner"],
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
    match = re.fullmatch(r"([^\s<>\[\]]+)[ \t]*->[ \t]*\[([0-9, \t]*)\]", output)
    if match is None:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    # Bind discovered ports to the requested IP, allowing equivalent IPv6 text.
    try:
        matches_target = ip_address(match.group(1)) == ip_address(target)
    except ValueError:
        matches_target = False

    if not matches_target:
        return RustScanResult(
            target=target,
            open_ports=[],
            status="error",
        )

    ports_text = match.group(2).strip()
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
