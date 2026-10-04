from importlib.metadata import version
from rich.console import Group
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from ..core.models import CommandRequest
from ..tools.dns import DNSResult
from ..tools.route import RouteTraceResult
from ..tools.rustscan import RustScanResult
from .runtime import console

from ..sequences.target_recon import TargetReconResult
from ..sequences.port_scan import PortScanResult

NETRUNNER_VERSION = version("netrunner-cnc")

def get_status_style(status: str) -> str:
    if status in ("not_answered", "unstable", "partial_success"):
        return "nr.warning"

    if status in ("error", "no_response", "not_found", "failed"):
        return "nr.error"

    if status in ("success",):
        return "nr.success"

    return "nr.text"

def clear_screen():
    console.clear()

def get_terminal_width() -> int:
    return console.width

def show_header():
    if get_terminal_width() < 90:
        show_compact_header()
        return

    logo = """[white]███╗   ██╗[/][nr.primary]███████╗████████╗[/][white]██████╗ [/][cyan]██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗[/]
[white]████╗  ██║[/][nr.primary]██╔════╝╚══██╔══╝[/][white]██╔══██╗[/][cyan]██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗[/]
[white]██╔██╗ ██║[/][nr.primary]█████╗     ██║   [/][white]██████╔╝[/][cyan]██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝[/]
[white]██║╚██╗██║[/][nr.primary]██╔══╝     ██║   [/][white]██╔══██╗[/][cyan]██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗[/]
[white]██║ ╚████║[/][nr.primary]███████╗   ██║   [/][white]██║  ██║[/][cyan]╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║[/]
[white]╚═╝  ╚═══╝[/][nr.primary]╚══════╝   ╚═╝   [/][white]╚═╝  ╚═╝[/][cyan] ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝[/]"""
    tagline = "[dim white]░▒[/][dim cyan]▓[/]  [white]SIGNAL[/] [cyan]//[/] [white]ROUTE[/] [cyan]//[/] [white]EXECUTE[/]  [dim cyan]▓[/][dim white]▒░[/]"
    subtitle = f"[dim white]COMMAND & CONTROL[/]"
    header = Group(
        Align.center(logo),
        Align.center(tagline),
        Align.center(subtitle),
    )
    console.print(
        Panel(
            header,
            border_style="nr.primary",
            subtitle=f"[nr.debug]v{NETRUNNER_VERSION}[/]",
            subtitle_align="right",
        )
    )

def show_compact_header():
    title = "[bold white]NET[/][bold cyan]RUNNER[/]"
    tagline = (
        "[dim cyan]░▒▓[/]  "
        "[white]SIGNAL[/] [cyan]//[/] [white]ROUTE[/] "
        "[cyan]//[/] [white]EXECUTE[/]  "
        "[dim cyan]▓▒░[/]"
    )
    subtitle = f"[dim white]COMMAND & CONTROL // v{NETRUNNER_VERSION}[/]"

    compact_header = Group(
        Align.center(title),
        Align.center(tagline),
        Align.center(subtitle),
    )

    console.print(
        Panel(
            compact_header,
            border_style="nr.primary",
        )
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

def show_main_menu():

    if get_terminal_width() < 46:
        menu = Table.grid(expand=True)
        menu.add_column()

        menu.add_row("[01] NETWORKING TOOLS")
        menu.add_row("[02] HEALTH CHECK")
        menu.add_row("[03] OSINT TOOLS")
        menu.add_row("[04] PENTESTING TOOLS")
        menu.add_row("[05] DEFENSE TOOLS")
        menu.add_row("[06] SYSTEM TOOLS")
        menu.add_row("[00] EXIT")
        panel = Panel(
            menu,
            title="[nr.primary]MAIN MENU[/]",
            border_style="nr.primary",
        )
        console.print(panel)
        return

    menu = Table.grid(expand=True)
    menu.add_column()
    menu.add_column()

    menu.add_row(
        "[01] NETWORKING TOOLS",
        "[02] HEALTH CHECK",
    )

    menu.add_row(
        "[03] OSINT TOOLS",
        "[04] PENTESTING TOOLS",
    )

    menu.add_row(
        "[05] DEFENSE TOOLS",
        "[06] SYSTEM TOOLS",
    )

    menu.add_row(
        "[00] EXIT",
        "",
    )

    panel = Panel(
        menu,
        title="[nr.primary]MAIN MENU[/]",
        border_style="nr.primary",
    )
    console.print(panel)

def show_networking_menu():
    menu = Table.grid(expand=True)
    menu.add_column()
    menu.add_column()

    menu.add_row(
        "[01] PING",
        "[02] DNS LOOKUP",
    )

    menu.add_row(
        "[03] ROUTE TRACE",
        "[04] PORT SCAN",
    )

    menu.add_row(
        "",
        "",
    )

    menu.add_row(
        "[11] TARGET RECON",
        "[00] BACK",
    )

    panel = Panel(
        menu,
        title="[nr.primary]NETWORKING TOOLS[/]",
        border_style="nr.primary",
    )
    console.print(panel)

def show_route_mode_menu(selected=None):
    compact_display = (
        "[nr.primary][01] COMPACT[/]"
        if selected == "compact"
        else "[01] COMPACT"
    )

    verbose_display = (
        "[nr.primary][02] VERBOSE[/]"
        if selected == "verbose"
        else "[02] VERBOSE"
    )

    menu = Table.grid(expand=True)
    menu.add_column()
    menu.add_column()

    menu.add_row(
        compact_display,
        verbose_display,
    )

    menu.add_row(
        "[00] BACK",
        "",
    )

    panel = Panel(
        menu,
        title="[nr.primary]ROUTE TRACE[/]",
        border_style="nr.primary",
    )
    console.print(panel)

def show_error(message: str):
    console.print(
        Panel(
            f"[nr.error]Error:[/] {message}",
            title="[nr.error]ERROR[/]",
            border_style="nr.error",
        ),
    )

def prompt(subject: str) -> str:
    console.print(f"[nr.primary]SELECT {subject} > [/]", end="")
    return input()

def prompt_input(subject: str, default=None) -> str:
    if default:
        console.print(f"[nr.primary]{subject} [{default}] > [/]", end="")
    else:
        console.print(f"[nr.primary]{subject} > [/]", end="")
    return input().strip()

def pause():
    console.print("[nr.primary]PRESS ENTER TO CONTINUE...[/]", end="")
    input()

def show_ping_result(result):
    resolved_ip_display = result.resolved_ip if result.resolved_ip is not None else "UNRESOLVED"

    status_display = result.status.replace("_", " ").upper()

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
        status_style = "nr.error"
    elif result.status == "no_response":
        packets_sent_style = "nr.success"
        packets_received_style = "nr.error"
        status_style = "nr.error"
    elif result.status == "unstable":
        packets_sent_style = "nr.success"
        packets_received_style = "nr.warning"
        status_style = "nr.warning"
    else:
        packets_sent_style = "nr.success"
        packets_received_style = "nr.success"
        status_style = "nr.success"

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
        f"  [nr.primary]Latency:[/] [{latency_style}] {latency_display}[/]\n"
        f"  [nr.primary]Status:[/] [{status_style}]{status_display}[/]"
    )
    console.print(
        Panel(
            content,
            title="PING RESULTS",
            border_style="nr.primary",
        ),
    )

def show_dns_result(result: DNSResult):
    answers_display = (
        "\n".join(f"    {answer}" for answer in result.answers)
        if result.answers
        else "    No answers received"
    )
    query_time_display = f"{result.query_time} ms" if result.query_time is not None else "N/A"
    server_display = result.server if result.server is not None else "N/A"

    content = (
        f"[nr.text]DNS Result for[/] [nr.success]{result.query}[/]:\n"
        f" [nr.primary]Record Type:[/] {result.record_type}\n"
        f" [nr.primary]Answers:[/]\n{answers_display}\n"
        f" [nr.primary]Query Time:[/] {query_time_display}\n"
        f" [nr.primary]Server:[/] {server_display}\n"
        f" [nr.primary]Status:[/] [nr.status]{result.status}[/]"
    )
    console.print(
        Panel(
            content,
            title="DNS RESULTS",
            border_style="nr.primary",
        ),
    )

def show_route_result(result: RouteTraceResult, verbose=False):

    destination_reached_display = "Destination Reached" if result.destination_reached else "Destination Not Reached"
    status_display = result.status.replace("_", " ").upper()
    destination_reached_style = "nr.success" if result.destination_reached else "nr.error"

    if result.status == "success":
        status_style = "nr.success"
    elif result.status == "partial_success":
        status_style = "nr.warning"
    else:
        status_style = "nr.error"

    content = (
        f"[nr.text]Route Trace Result for[/] [nr.success]{result.target}[/]:\n"
        f"  [nr.primary]Destination IP:[/] [nr.success]{result.destination_ip}[/]\n"
        f"  [nr.primary]Total Hops:[/] {len(result.hops)}\n"
        f"  [nr.primary]Responding Hops:[/] {result.responding_hops}\n"
        f"  [nr.primary]Destination:[/] [{destination_reached_style}]{destination_reached_display}[/]\n"
        f"  [nr.primary]Status:[/] [{status_style}]{status_display}[/]"
    )

    console.print(
        Panel(
            content,
            title="ROUTE TRACE RESULTS",
            border_style="nr.primary"
        )
    )

    if verbose:
        route_lines = []

        for hop in result.hops:
            hop_number_display = f"{hop.hop_number:02d}"

            probe_displays = []
            routers = set()
            for probe in hop.probes:
                if probe.response_time is None:
                    probe_display = "*"
                else:
                    probe_display = f"{probe.response_time:.3f} ms"
                    routers.add((probe.hostname, probe.ip))

                probe_displays.append(probe_display)

            probe_summary = " / ".join(probe_displays)

            if len(routers) == 0:
                route_lines.append(
                    f"[nr.primary]{hop_number_display}[/] [nr.error]NO RESPONSE[/]"
                )
                route_lines.append(
                    f"    [nr.error]{probe_summary}[/]"
                )
            elif len(routers) == 1:
                hostname, ip = next(iter(routers))
                router_display = f"{hostname} ({ip})" if hostname != ip else ip

                route_lines.append(
                    f"[nr.primary]{hop_number_display}[/] [nr.text]{router_display}[/]"
                )
                route_lines.append(
                    f"    [nr.status]{probe_summary}[/]"
                )
            else:
                for index, probe in enumerate(hop.probes):
                    if index == 0:
                        prefix = f"[nr.primary]{hop_number_display}[/] "
                    else:
                        prefix = "    "

                    if probe.response_time is None:
                        probe_line = f"[nr.error]*[/]"

                    else:
                        router_display = f"{probe.hostname} ({probe.ip})" if probe.hostname != probe.ip else probe.ip
                        latency_display = f"{probe.response_time:.3f} ms"
                        probe_line = (
                            f"[nr.text]{router_display}[/] "
                            f"[nr.status]{latency_display}[/]"
                        )

                    route_lines.append(prefix + probe_line)

        route_content = "\n".join(route_lines)

        console.print(
            Panel(
                route_content,
                title="ROUTE",
                border_style="nr.primary"
            )
        )

def show_rustscan_result(result: RustScanResult):

    open_ports_display = (
        ", ".join(str(port) for port in result.open_ports)
        if result.open_ports
        else "None discovered"
    )

    status_display = result.status.replace("_", " ").upper()

    if result.status == "rustscan_error":
        status_style = "nr.error"
    elif result.status == "no_ports_discovered":
        status_style = "nr.warning"
    else:
        status_style = "nr.success"

    content = (
        f"[nr.text]RustScan Result for[/] [nr.success]{result.target}[/]:\n"
        f"  [nr.primary]Open Ports:[/] {open_ports_display}\n"
        f"  [nr.primary]Total Open Ports:[/] {len(result.open_ports)}\n"
        f"  [nr.primary]Status:[/] [{status_style}]{status_display}[/]"
    )
    console.print(
        Panel(
            content,
            title="RUSTSCAN RESULTS",
            border_style="nr.primary",
        ),
    )

def show_nmap_result(result):

    status_display = result.status.replace("_", " ").upper()
    resolved_ip_display = result.resolved_ip if result.resolved_ip is not None else "N/A"
    hostname_display = result.hostname if result.hostname is not None else "N/A"
    host_state_display = result.host_state.upper() if result.host_state is not None else "UNKNOWN"
    elapsed_display = f"{result.elapsed:.2f}s" if result.elapsed is not None else "N/A"
    total_ports_display = f"{len(result.ports)}" if result.ports else "0"
    scanned_ports_display = f"{result.scanned_ports}" if result.scanned_ports is not None else "No ports scanned"

    if result.status in {"nmap_error", "parse_error", "no_output"}:
        status_style = "nr.error"
    elif result.status == "no_open_ports":
        status_style = "nr.warning"
    else:
        status_style = "nr.success"


    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="nr.primary", width=17)
    summary.add_column(style="nr.text")

    summary.add_row("Target:", f"[nr.success]{result.target}[/]")
    summary.add_row("Resolved IP:", resolved_ip_display)
    summary.add_row("Hostname:", hostname_display)
    summary.add_row("Host State:", host_state_display)
    summary.add_row("Scanned Ports:", scanned_ports_display)
    summary.add_row("Open Ports:", total_ports_display)
    summary.add_row("Elapsed Time:", elapsed_display)
    summary.add_row("Status:", f"[{status_style}]{status_display}[/]")

    ports_table = Table(
        show_header=True,
        header_style="nr.primary",
        box=None,
        expand=False,
    )

    ports_table.add_column("PORT")
    ports_table.add_column("PROTOCOL")
    ports_table.add_column("STATE")
    ports_table.add_column("SERVICE")
    ports_table.add_column("PRODUCT")
    ports_table.add_column("VERSION")

    for port in result.ports:
        ports_table.add_row(
            str(port.port),
            port.protocol,
            port.state,
            port.service if port.service is not None else "N/A",
            port.product if port.product is not None else "N/A",
            port.version if port.version is not None else "N/A"
        )

    panel_content = Group(
        summary,
        "",
        ports_table,
    )

    console.print(
        Panel(
            panel_content,
            title="NMAP RESULTS",
            border_style="nr.primary",
        ),
    )

def show_port_scan_result(result: PortScanResult):

    rustscan_status_display = result.rustscan.status.replace("_", " ").upper()
    nmap_status_display = result.nmap.status.replace("_", " ").upper() if result.nmap else "N/A"
    status_display = result.status.replace("_", " ").upper()

    if result.status in {"rustscan_error", "nmap_error", "parse_error", "no_output"}:
        status_style = "nr.error"
    elif result.status in {"no_ports_discovered", "no_open_ports"}:
        status_style = "nr.warning"
    else:
        status_style = "nr.success"

    if result.rustscan.status == "error":
        rustscan_status_style = "nr.error"
    elif result.rustscan.status == "no_ports_discovered":
        rustscan_status_style = "nr.warning"
    else:
        rustscan_status_style = "nr.success"

    if result.nmap is None:
        nmap_status_style = "nr.text"
    elif result.nmap.status in {"error", "parse_error", "no_output"}:
        nmap_status_style = "nr.error"
    elif result.nmap.status == "no_open_ports":
        nmap_status_style = "nr.warning"
    else:
        nmap_status_style = "nr.success"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="nr.primary", width=17)
    summary.add_column(style="nr.text")
    summary.add_column(style="nr.text")

    summary.add_row("Target:", f"[nr.success]{result.target}[/]")
    summary.add_row(
        "Discovery Engine:",
        "[nr.primary]RustScan[/]",
        f"[{rustscan_status_style}]{rustscan_status_display}[/]",
        )
    summary.add_row(
        "Analysis Engine:",
        "[nr.primary]Nmap[/]",
        f"[{nmap_status_style}]{nmap_status_display}[/]",
        )
    summary.add_row("Ports Discovered:", f"[nr.success]{len(result.rustscan.open_ports)}[/]")
    summary.add_row("Ports Analyzed:", f"[nr.success]{result.nmap.scanned_ports if result.nmap else 0}[/]")
    summary.add_row("Status:", f"[{status_style}]{status_display}[/]")

    if result.nmap is not None and result.nmap.ports:
        ports_table = Table(
            show_header=True,
            header_style="nr.primary",
            box=None,
            expand=False,
        )

        ports_table.add_column("PORT")
        ports_table.add_column("PROTOCOL")
        ports_table.add_column("STATE")
        ports_table.add_column("SERVICE")
        ports_table.add_column("PRODUCT")
        ports_table.add_column("VERSION")

        panel_content = Group(
            summary,
            "",
            ports_table,
        )
    else:
        panel_content = summary

    if result.nmap is not None:
        for port in result.nmap.ports:
            ports_table.add_row(
                str(port.port),
                port.protocol,
                port.state,
                port.service if port.service is not None else "N/A",
                port.product if port.product is not None else "N/A",
                port.version if port.version is not None else "N/A",
            )

    console.print(
        Panel(
            panel_content,
            title="PORT SCAN RESULTS",
            border_style="nr.primary",
        ),
    )

def show_recon_result(result: TargetReconResult):

    address = result.dns_result.answers[0] if result.dns_result.answers else "N/A"
    packet_loss = (
        f"{result.ping_result.packet_loss:g}%"
        if result.ping_result.packet_loss is not None
        else "N/A"
    )
    latency = (
        f"{result.ping_result.latency_avg:.1f} ms"
        if result.ping_result.latency_avg is not None
        else "N/A"
    )

    hops = (
        f"{result.route_result.responding_hops}/{len(result.route_result.hops)} responding"
        if result.route_result.hops
        else "N/A"
    )

    destination = (
        "[nr.success]REACHED[/]"
        if result.route_result.destination_reached
        else "[nr.warning]NOT REACHED[/]"
    )
    dns_status = result.dns_result.status.replace("_", " ").upper()
    ping_status = result.ping_result.status.replace("_", " ").upper()
    route_status = result.route_result.status.replace("_", " ").upper()

    table = Table.grid(padding=(0, 2))
    table.add_column(style="nr.primary")
    table.add_column(style="nr.text")
    table.add_column(style="nr.text")

    table.add_row(
        "Target:",
        result.target,
    )
    table.add_row(
        "Address:",
        address,
    )
    table.add_row("", "", "")
    table.add_row(
        "DNS:",
        f"[{get_status_style(result.dns_result.status)}]{dns_status}[/]",
    )
    table.add_row(
        "Ping:",
        f"[{get_status_style(result.ping_result.status)}]{ping_status}[/]",
        f"{packet_loss} loss / {latency}",
    )
    table.add_row(
        "Route:",
        f"[{get_status_style(result.route_result.status)}]{route_status}[/]",
        hops,
    )
    table.add_row("", "", "")
    table.add_row(
        "Destination:",
        destination,
    )
    table.add_row("", "", "")

    footer = "[nr.debug]For comprehensive results, run each tool individually.[/]"

    report = Group(
        table,
        footer,
    )

    console.print(
        Panel(
            report,
            title="TARGET RECON",
            border_style="nr.primary",
            expand=False,
            )
        )
