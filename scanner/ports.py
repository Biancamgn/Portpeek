"""
ports.py -- Port scanning (the "port scanning" requirement).

Two scan types, so the tool can talk about the classic tradeoff NMAP makes:

  * connect scan (-sT style)  -- full TCP handshake via the OS socket API.
                                 Needs no privileges, always works, but is
                                 noisier (the target logs a real connection).
  * SYN scan     (-sS style)  -- half-open. scapy sends a lone SYN and reads
                                 the reply: SYN/ACK = open, RST = closed.
                                 Faster and stealthier, but needs root.

The public scan_ports() picks SYN when asked and privileged, otherwise falls
back to connect so a demo never dies just because root was missing.
"""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from scapy.all import IP, TCP, sr1


@dataclass
class PortResult:
    port: int
    state: str                    # "open", "closed", "filtered"
    service: str = ""             # filled by services.py
    product: str = ""
    version: str = ""
    banner: str = ""
    vulns: list = None            # filled by vulns.py

    def __post_init__(self):
        if self.vulns is None:
            self.vulns = []


# A compact, demo-friendly default set covering the interesting Metasploitable
# and Windows services. Override on the CLI with -p.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 512, 513,
    514, 993, 995, 1099, 1433, 1524, 2049, 2121, 3306, 3389, 5432, 5900,
    6000, 6667, 8009, 8080, 8180,
]


def parse_ports(spec: str) -> list[int]:
    """
    Turn a port spec into a sorted, de-duplicated list.

    Accepts "22", "1-1024", "22,80,443", or a mix like "22,80,8000-8100".
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > 65535:
                raise ValueError(f"Bad port range '{part}'")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"Port out of range '{part}'")
            ports.add(p)
    return sorted(ports)


def _connect_scan_port(ip: str, port: int, timeout: float) -> PortResult:
    """One TCP connect() attempt. open on success, closed/filtered otherwise."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return PortResult(port, "open")
            return PortResult(port, "closed")
        except socket.timeout:
            return PortResult(port, "filtered")
        except OSError:
            return PortResult(port, "filtered")


def _syn_scan_port(ip: str, port: int, timeout: float) -> PortResult:
    """One half-open SYN probe via scapy."""
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=False)
    if resp is None:
        return PortResult(port, "filtered")
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:            # SYN/ACK -> open
            # Be polite: tear down the half-open connection with a RST.
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"),
                timeout=1, verbose=False)
            return PortResult(port, "open")
        if flags == 0x14:            # RST/ACK -> closed
            return PortResult(port, "closed")
    return PortResult(port, "filtered")


def scan_ports(ip: str, ports: list[int] | None = None, scan_type: str = "auto",
               timeout: float = 1.0, workers: int = 100,
               verbose: bool = False) -> list[PortResult]:
    """
    Scan `ports` on a single host and return only the OPEN ports.

    scan_type:
      "connect" -- force TCP connect
      "syn"     -- force SYN (requires root)
      "auto"    -- SYN if root, else connect (with a heads-up)
    """
    if ports is None:
        ports = COMMON_PORTS

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if scan_type == "auto":
        chosen = "syn" if is_root else "connect"
    else:
        chosen = scan_type
        if chosen == "syn" and not is_root:
            if verbose:
                print("  [!] SYN scan needs root; falling back to connect scan.")
            chosen = "connect"

    probe = _syn_scan_port if chosen == "syn" else _connect_scan_port
    open_ports: list[PortResult] = []

    # Thread the scan so a wide port list finishes fast during a live demo.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res.state == "open":
                open_ports.append(res)
                if verbose:
                    print(f"  [+] {ip}:{res.port} open")

    open_ports.sort(key=lambda r: r.port)
    return open_ports
