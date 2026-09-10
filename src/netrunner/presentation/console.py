from rich.console import Console, Group
from rich.theme import Theme
from rich.panel import Panel
from rich.align import Align

from ..core.models import CommandRequest

netrunner_theme = Theme(
    {
        "nr.primary": "bold cyan",
        "nr.text": "white",
        "nr.error": "bold red",
        "nr.success": "bold green",
        "nr.warning": "bold yellow",
        "nr.info": "bold blue",
        "nr.debug": "dim white",
        "nr.command": "bold magenta",
        "nr.argument": "yellow",
        "nr.description": "italic white",
        "nr.result": "bold green",
        "nr.status": "bold cyan",
        "nr.latency": "bold yellow",
        "nr.packet_loss": "bold red",
        "nr.packets_sent": "bold green",
        "nr.packets_received": "bold green",
    }
)

console = Console(theme=netrunner_theme)

def show_header():
    logo = """
    [white]███╗   ██╗[/][nr.primary]███████╗████████╗[/][white]██████╗ [/][cyan] ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗[/]
    [white]████╗  ██║[/][nr.primary]██╔════╝╚══██╔══╝[/][white]██╔══██╗[/][cyan] ██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗[/]
    [white]██╔██╗ ██║[/][nr.primary]█████╗     ██║   [/][white]██████╔╝[/][cyan] ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝[/]
    [white]██║╚██╗██║[/][nr.primary]██╔══╝     ██║   [/][white]██╔══██╗[/][cyan] ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗[/]
    [white]██║ ╚████║[/][nr.primary]███████╗   ██║   [/][white]██║  ██║[/][cyan] ╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║[/]
    [white]╚═╝  ╚═══╝[/][nr.primary]╚══════╝   ╚═╝   [/][white]╚═╝  ╚═╝[/][cyan]  ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝[/]"""
    tagline = "[dim white]░▒[/][dim cyan]▓[/]  [white]SIGNAL[/] [cyan]//[/] [white]ROUTE[/] [cyan]//[/] [white]EXECUTE[/]  [dim cyan]▓[/][dim white]▒░[/]"
    subtitle = "[dim white]COMMAND & CONTROL[/]"
    header = Group(
        Align.center(logo),
        Align.center(tagline),
        Align.center(subtitle),
    )
    console.print(
        Panel(
            header,
            border_style="nr.primary",
        ),
    )

def show_request(request: CommandRequest):
    arguments = ", ".join(request.arguments)
    content = (
        f"[nr.primary]Command:[/] [nr.command]{request.program}[/]\n"
        f"[nr.primary]Arguments:[/] [nr.argument]{arguments}[/]\n"
        f"[nr.primary]Description:[/] [nr.description]{request.description}[/]"
    )
    console.print(
        Panel(
            content,
            title="COMMAND",
            border_style="nr.primary",
        ),
    )


def show_ping_result(result):
    resolved_ip_display = result.resolved_ip if result.resolved_ip is not None else "UNRESOLVED"

    packet_loss_display = (
        f"{result.packet_loss}%"
        if result.packet_loss is not None
        else "N/A"
    )

    latency_display = (
        f"{result.latency_min}/{result.latency_avg}/{result.latency_max} ms"
        if result.latency_min is not None
        else "N/A"
    )

    if result.status == "error":
        packets_sent_style = "nr.error"
        packets_received_style = "nr.error"
    elif result.status == "unreachable":
        packets_sent_style = "nr.success"
        packets_received_style = "nr.error"
    elif result.status == "unstable":
        packets_sent_style = "nr.success"
        packets_received_style = "nr.warning"
    else:
        packets_sent_style = "nr.success"
        packets_received_style = "nr.success"

    if result.packet_loss is None:
        packet_loss_style = "nr.error"
    elif result.packet_loss == 0.0:
        packet_loss_style = "nr.success"
    elif result.packet_loss < 100:
        packet_loss_style = "nr.warning"
    else:
        packet_loss_style = "nr.error"

    if result.latency_avg is None:
        latency_style = "nr.error"
    elif result.latency_avg < 50:
        latency_style = "nr.success"
    elif result.latency_avg >= 50 and result.latency_avg < 100:
        latency_style = "nr.status"
    elif result.latency_avg >= 100 and result.latency_avg < 200:
        latency_style = "nr.warning"
    else:
        latency_style = "nr.error"

    content = (
        f"[nr.text]Ping Result for[/] [nr.success]{result.target}[/]:\n"
        f"  [nr.primary]Resolved IP:[/] {resolved_ip_display}\n"
        f"  [nr.primary]Packets Sent:[/] [{packets_sent_style}]{result.packets_sent}[/]\n"
        f"  [nr.primary]Packets Received:[/] [{packets_received_style}]{result.packets_received}[/]\n"
        f"  [nr.primary]Packet Loss:[/] [{packet_loss_style}]{packet_loss_display}[/]\n"
        f"  [nr.primary]Latency (min/avg/max):[/] [{latency_style}] {latency_display}[/]\n"
        f"  [nr.primary]Status:[/] [nr.status]{result.status}[/]"
    )
    console.print(
        Panel(
            content,
            title="PING RESULTS",
            border_style="nr.primary",
        ),
    )

