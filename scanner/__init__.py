"""
portpeek.scanner
===============

Core scanning engine, split into one module per capability so the
architecture mirrors the four required features plus the vuln twist:

    discovery    -> host discovery (ARP sweep + ICMP ping sweep)
    ports        -> port scanning (TCP connect + SYN)
    services     -> service and version detection (banner grabbing)
    fingerprint  -> OS fingerprinting (TTL / TCP window heuristics)
    vulns        -> flag outdated / vulnerable versions (the twist)
"""

from . import discovery, ports, services, fingerprint, vulns

__all__ = ["discovery", "ports", "services", "fingerprint", "vulns"]
