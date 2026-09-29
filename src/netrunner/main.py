from .workflows import run_ping, run_dns
from .interaction import run_main_menu
from .presentation.console import(
     show_error,
     prompt_input,
     show_header,
     show_request,
     show_dns_result,
     show_ping_result,
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
