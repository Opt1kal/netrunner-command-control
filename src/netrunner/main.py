from .tools.ping import build_ping_request, parse_ping_result
from .core.runner import run_command
from .presentation.console import show_header, show_ping_result, show_request

def main():
    show_header()

    target = ""
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
