from .tools.ping import build_ping_request, parse_ping_result
from .tools.dns import build_dns_request, parse_dns_result
from .core.runner import run_command
from .presentation.console import show_header, show_ping_result, show_request, show_error, show_dns_result
import argparse

def run_dns(query=None, record_type=None):
    show_header()

    while not query:
        query = input("Enter a domain name or IP address to perform a DNS lookup (e.g., example.com): ").strip()

        if not query:
            print("Query cannot be empty. Please enter a valid domain name or IP address.")
    if not record_type:
        record_type = input("Enter the DNS record type to query (e.g., A, AAAA, MX, CNAME) [default: A]: ").strip().upper()
        if not record_type:
            record_type = "A"
    else:
        record_type = record_type.upper()

    request = build_dns_request(query=query, record_type=record_type)
    result = run_command(request)
    dns_result = parse_dns_result(result)

    show_request(request)
    show_dns_result(dns_result)

def run_ping(target=None):
    show_header()

    while not target:
        target = input("Enter a target to ping (e.g., google.com): ").strip()
        if not target:
            print(
                "Target cannot be empty. Please enter a valid target."
            )

    request = build_ping_request(target=target, count=5)
    result = run_command(request)
    ping_result = parse_ping_result(result)

    show_request(request)
    show_ping_result(ping_result)


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
        show_header()
        show_error("No command provided. Please specify a command to run. Use 'nrc -h' for a list of available commands."
                   )
    elif args.command == "ping":
        run_ping(target=args.target)
    elif args.command == "dns":
        run_dns(args.query, args.record_type)
