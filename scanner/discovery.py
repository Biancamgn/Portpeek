"""
discovery.py -- Host discovery (the "ping sweep" requirement).

Two techniques, mirroring what NMAP does on a local network:

  * ARP sweep  -- Layer-2. The reliable choice on a host-only LAN because
                  a host must answer ARP to speak IP at all, even when its
                  firewall silently drops ICMP. This is exactly why it finds
                  the Windows 7 VM (whose firewall blocks ping) where a plain
                  ICMP sweep would miss it.
  * ICMP sweep -- Layer-3 echo request/reply. Works across subnets/routed
                  networks where ARP cannot reach.

Both need root (raw sockets). The caller is expected to have checked for
privileges; if scapy raises for lack of them we surface a clean error rather
than a stack trace.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from scapy.all import ARP, Ether, IP, ICMP, srp, sr


@dataclass
class Host:
    """A single discovered host and everything we learn about it later."""
    ip: str
    mac: str | None = None
    method: str = ""              # how it was found: "arp" or "icmp"
    os_guess: str = ""            # filled in by fingerprint.py
    ports: list = field(default_factory=list)   # filled in by ports/services


def _expand_targets(target: str) -> list[str]:
    """
    Turn a user target string into a list of host IPs.

    Accepts a single IP ("192.168.56.101"), CIDR ("192.168.56.0/24"),
    or a comma-separated mix of both.
    """
    hosts: list[str] = []
    for chunk in target.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "/" in chunk:
                net = ipaddress.ip_network(chunk, strict=False)
                hosts.extend(str(h) for h in net.hosts())
            else:
                hosts.append(str(ipaddress.ip_address(chunk)))
        except ValueError as exc:
            raise ValueError(f"Invalid target '{chunk}': {exc}") from exc
    return hosts


def arp_sweep(target: str, timeout: int = 2, verbose: bool = False) -> list[Host]:
    """
    ARP-scan a local subnet. Returns the hosts that answered.

    Uses a single broadcast srp() so the whole subnet is probed in one shot
    rather than one packet at a time -- fast and easy to demo.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    try:
        answered, _ = srp(pkt, timeout=timeout, verbose=False)
    except PermissionError:
        raise PermissionError("ARP sweep needs root. Re-run with sudo.")

    hosts: list[Host] = []
    for _sent, recv in answered:
        hosts.append(Host(ip=recv.psrc, mac=recv.hwsrc, method="arp"))
        if verbose:
            print(f"  [arp] {recv.psrc:<15} {recv.hwsrc}")
    return hosts


def icmp_sweep(target: str, timeout: int = 2, verbose: bool = False) -> list[Host]:
    """
    ICMP echo (ping) sweep. Fallback for routed networks where ARP can't reach.

    Sends one echo request per host. Slower than the ARP broadcast but works
    off-subnet.
    """
    ips = _expand_targets(target)
    packets = [IP(dst=ip) / ICMP() for ip in ips]
    try:
        answered, _ = sr(packets, timeout=timeout, verbose=False)
    except PermissionError:
        raise PermissionError("ICMP sweep needs root. Re-run with sudo.")

    hosts: list[Host] = []
    for _sent, recv in answered:
        hosts.append(Host(ip=recv.src, method="icmp"))
        if verbose:
            print(f"  [icmp] {recv.src} replied (ttl={recv.ttl})")
    return hosts


def discover(target: str, mode: str = "auto", timeout: int = 2,
             verbose: bool = False) -> list[Host]:
    """
    Top-level discovery entry point.

    mode:
      "arp"  -- ARP only
      "icmp" -- ICMP only
      "auto" -- ARP first (best on a local lab LAN); if nothing answers,
                fall back to ICMP.

    Returns a de-duplicated, sorted list of Host objects.
    """
    found: dict[str, Host] = {}

    if mode in ("arp", "auto"):
        for h in arp_sweep(target, timeout, verbose):
            found[h.ip] = h

    if mode == "icmp" or (mode == "auto" and not found):
        for h in icmp_sweep(target, timeout, verbose):
            found.setdefault(h.ip, h)

    return sorted(found.values(), key=lambda h: ipaddress.ip_address(h.ip))
