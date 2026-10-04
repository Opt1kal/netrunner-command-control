from dataclasses import dataclass

from ..tools.rustscan import RustScanResult
from ..tools.nmap import NmapResult
from ..workflows import run_rustscan, run_nmap
from collections.abc import Callable

@dataclass
class PortScanResult:
    target: str
    rustscan: RustScanResult
    nmap: NmapResult | None
    status: str

def run_port_scan(
    target: str,
    progress: Callable[[str, str], None] | None = None,
) -> PortScanResult:
    def report(step: str, status: str):
        if progress is not None:
            progress(step, status)

    report("rustscan", "running")
    _, rustscan_result = run_rustscan(target)
    report("rustscan", "complete")

    nmap_result = None
    if rustscan_result.status == "success" and rustscan_result.open_ports:
        report("nmap", "running")
        _, nmap_result = run_nmap(target, ports=rustscan_result.open_ports)
        report("nmap", "complete")

    if rustscan_result.status == "error":
        status = "rustscan_error"
    elif rustscan_result.status == "no_ports_discovered":
        status = "no_ports_discovered"
    elif nmap_result is None:
        status = "nmap_error"
    elif nmap_result.status == "error":
        status = "nmap_error"
    else:
        status = nmap_result.status

    return PortScanResult(
        target=target,
        rustscan=rustscan_result,
        nmap=nmap_result,
        status=status,
    )