from dataclasses import dataclass
from ..core.models import CommandRequest, CommandResult

def build_ping_request(target: str, count: int) -> CommandRequest:
    """
    Build a CommandRequest for the ping command.

    Args:
        target (str): The target host to ping.
        count (int): The number of ping requests to send.

    Returns:
        CommandRequest: A CommandRequest object for the ping command.
    """
    return CommandRequest(
        program="ping",
        arguments=["-4", "-c", str(count), target],
        description=f"Ping {target} {count} times",
    )

@dataclass
class PingResult:
    """
    A dataclass to represent the result of a ping command.

    Attributes:
        target (str): The target host that was pinged.
        count (int): The number of ping requests sent.
        resolved_ip (str | None): The resolved IP address of the target host.
        packets_sent (int): The number of packets sent.
        packets_received (int): The number of packets received.
        packet_loss (float | None): The percentage of packet loss.
        latency_min (float | None): The minimum latency in milliseconds.
        latency_avg (float | None): The average latency in milliseconds.
        latency_max (float | None): The maximum latency in milliseconds.
        status (str): The status of the ping command (e.g., "success", "unstable", "unreachable", or "error").
    """
    target: str
    resolved_ip: str | None
    packets_sent: int
    packets_received: int
    packet_loss: float | None
    latency_min: float | None
    latency_avg: float | None
    latency_max: float | None
    status: str
    count: int

def parse_ping_result(result: CommandResult) -> PingResult:
    """
    Parse the result of a ping command into a PingResult object.

    Args:
        result (CommandResult): The result of the ping command.

    Returns:
        PingResult: A PingResult object containing parsed information from the ping command output.
    """

    lines = result.stdout.splitlines()

    header_line = None
    packet_stats_line = None
    latency_stats_line = None

    for line in lines:
        if line.startswith("PING"):
            header_line = line
        elif "packets transmitted" in line:
            packet_stats_line = line
        elif "min/avg/max" in line:
            latency_stats_line = line

    resolved_ip = None

    if header_line:
        resolved_ip = extract_resolved_ip(header_line)

    packets_sent = 0
    packets_received = 0
    packet_loss = None

    if packet_stats_line:
        packets_sent, packets_received, packet_loss = extract_packet_stats(packet_stats_line)

    latency_min = None
    latency_avg = None
    latency_max = None

    if latency_stats_line:
        latency_min, latency_avg, latency_max = extract_latency_stats(latency_stats_line)

    count_index = result.request.arguments.index("-c") + 1
    count = int(result.request.arguments[count_index])
    target = result.request.arguments[-1]

    if not packet_stats_line:
        status = "error"
    elif packets_received > 0 and packets_received == packets_sent:
        status = "success"
    elif packets_received > 0 and packets_received < packets_sent:
        status = "unstable"
    else:
        status = "no_response"

    return PingResult(
        target=target,
        resolved_ip=resolved_ip,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packet_loss=packet_loss,
        latency_min=latency_min,
        latency_avg=latency_avg,
        latency_max=latency_max,
        status=status,
        count=count,
    )

def extract_resolved_ip(output: str) -> str | None:
    """
    Extract the resolved IP address from the ping command output.

    Args:
        output (str): The output of the ping command.

    Returns:
        str | None: The resolved IP address of the target host, or None if not found.
    """
    # Implementation for extracting resolved IP address
    if "(" not in output or ")" not in output:
        return None

    return output.split("(")[1].split(")")[0]

def extract_packet_stats(stats: str) -> tuple[int, int, float]:
    """
    Extract packet statistics from the ping command output.

    Args:
        stats (str): The packet statistics line from the ping command output.

    Returns:
        tuple[int, int, float]: A tuple containing packets sent, packets received, and packet loss percentage.
    """
    parts = stats.split(", ")
    packets_sent = int(parts[0].split()[0])
    packets_received = int(parts[1].split()[0])
    packet_loss = float(parts[2].split()[0].replace("%", ""))
    return packets_sent, packets_received, packet_loss

def extract_latency_stats(latency: str) -> tuple[float, float, float]:
    """
    Extract latency statistics from the ping command output.

    Args:
        latency (str): The latency statistics line from the ping command output.

    Returns:
        tuple[float, float, float]: A tuple containing minimum, average, and maximum latency in milliseconds.
    """
    parts = latency.split(" = ")[1].split("/")
    latency_min = float(parts[0])
    latency_avg = float(parts[1])
    latency_max = float(parts[2])
    return latency_min, latency_avg, latency_max
