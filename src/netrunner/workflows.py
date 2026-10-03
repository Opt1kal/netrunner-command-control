from .tools.ping import build_ping_request, parse_ping_result
from .tools.dns import build_dns_request, parse_dns_result
from .tools.route import build_route_request, parse_route_result
from .tools.rustscan import build_rustscan_request, parse_rustscan_result
from .core.runner import run_command

def run_dns(query, record_type):
    request = build_dns_request(query=query, record_type=record_type)
    result = run_command(request)
    dns_result = parse_dns_result(result)

    return request, dns_result

def run_ping(target):
    request = build_ping_request(target=target, count=5)
    result = run_command(request)
    ping_result = parse_ping_result(result)

    return request, ping_result

def run_route(target):
    request = build_route_request(target=target)
    result = run_command(request)
    route_result = parse_route_result(result)

    return request, route_result

def run_rustscan(target):
    request = build_rustscan_request(target=target)
    result = run_command(request)
    rustscan_result = parse_rustscan_result(result)

    return request, rustscan_result
