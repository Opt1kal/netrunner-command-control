from .workflows import run_ping, run_dns, run_route
from .interaction import run_main_menu
from .sequences.port_scan import run_port_scan
from .sequences.target_recon import run_target_recon
from .presentation.activity import run_with_activity
from .presentation.console import(
     show_error,
     prompt_input,
     show_header,
     show_request,
     show_dns_result,
     show_ping_result,
     show_route_result,
     show_recon_result,
     show_port_scan_result,
)
import argparse

def main():
    parser = argparse.ArgumentParser(
        prog="nrc",
        description="NETRUNNER // COMMAND & CONTROL",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    ping_parser = subparsers.add_parser("ping", help="Send ICMP echo requests to a target host and display the results.")
    ping_parser.add_argument("target", nargs="?", help="The target host to ping")

    dns_parser = subparsers.add_parser("dns", help="Perform a DNS lookup for a domain name or IP address.")
    dns_parser.add_argument("query", nargs="?", help="The domain name or IP address to query")
    dns_parser.add_argument("record_type", nargs="?", help="The DNS record type to query [default: A]")

    route_parser = subparsers.add_parser(
        "route",
        help="Trace the network route to a target host.",
    )
    route_parser.add_argument(
        "target",
        nargs="?",
        help="The target host to trace",
    )

    recon_parser = subparsers.add_parser(
        "recon",
        help="Perform consolidated reconnaissance against a target.",
    )
    recon_parser.add_argument(
        "target",
        nargs="?",
        help="The target host to investigate",
    )

    portscan_parser = subparsers.add_parser(
    "portscan",
    help="Discover open ports with RustScan and analyze detected services with Nmap.",
    )
    portscan_parser.add_argument(
        "target",
        nargs="?",
        help="The target host to scan",
    )

    args = parser.parse_args()

    if not args.command:
        run_main_menu()
    elif args.command == "ping":
        target = args.target

        while not target:
            target = prompt_input("TARGET")

            if not target:
                show_error("Target cannot be empty.")

        request, ping_result = run_ping(target)

        show_header()
        show_request(request)
        show_ping_result(ping_result)
    elif args.command == "dns":
        query=args.query
        record_type=args.record_type or "A"

        while not query:
            query = prompt_input("QUERY")

            if not query:
                show_error("Query cannot be empty.")

        record_type = record_type.upper()

        request, dns_result = run_dns(query, record_type)

        show_header()
        show_request(request)
        show_dns_result(dns_result)

    elif args.command == "recon":
        target = args.target

        while not target:
            target = prompt_input("TARGET")

            if not target:
                show_error("Target cannot be empty.")

        progress_state = {
            "dns": "waiting",
            "ping": "waiting",
            "route": "waiting",
        }

        def update_progress(step: str, status: str):
            progress_state[step] = status

        recon_result = run_with_activity(
            "TARGET RECON",
            run_target_recon,
            target,
            update_progress,
            progress_state=progress_state,
        )

        show_header()
        show_recon_result(recon_result)

    elif args.command == "route":
        target = args.target

        while not target:
            target = prompt_input("TARGET")

            if not target:
                show_error("Target cannot be empty.")

        request, route_result = run_with_activity(
            "ROUTE TRACE",
            run_route,
            target,
        )

        show_header()
        show_request(request)
        show_route_result(route_result)
    elif args.command == "portscan":
        target = args.target

        while not target:
            target = prompt_input("TARGET")

            if not target:
                show_error("Target cannot be empty.")

        PortScanResult = run_with_activity(
            "PORT SCAN",
            run_port_scan,
            target,
        )

        show_header()
        show_port_scan_result(PortScanResult)