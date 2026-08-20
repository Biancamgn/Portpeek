"""
services.py -- Service and version detection (the "service/version" requirement).

For every open port we:
  1. name the service from a port->service table (a first guess),
  2. grab a banner (read whatever the service says on connect, and for quiet
     protocols like HTTP send a tiny probe to make it talk),
  3. run the banner against a list of regexes to pull out product + version.

The product/version we extract here is what the vulns module later looks up,
so this module is the bridge between "what's running" and "is it dangerous".
"""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data" / "services.json"


def _load_db() -> dict:
    with open(_DATA, "r", encoding="utf-8") as fh:
        return json.load(fh)


_DB = _load_db()
_DEFAULT_PORTS: dict = _DB.get("default_ports", {})
_PROBES: dict = _DB.get("probes", {})
_PATTERNS: list = _DB.get("version_patterns", [])


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect, optionally send a protocol probe, and read the first response.

    Returns the decoded banner (may be empty). All socket errors are swallowed
    and turned into an empty banner so one dead port never aborts the scan.
    """
    data = b""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            probe = _PROBES.get(str(port))
            if probe:
                s.sendall(probe.encode("latin-1", errors="ignore"))

            data = s.recv(2048)
    except (socket.timeout, OSError):
        return ""
    return data.decode("latin-1", errors="replace").strip()


def _match_version(service: str, banner: str) -> tuple[str, str]:
    """
    Try every regex whose service matches (or is generic) against the banner.

    Returns (product, version); either may be "" if nothing matched.
    """
    for pat in _PATTERNS:
        if pat["service"] not in ("", service) and service:
            # patterns are loosely scoped by service, but still allow a
            # cross-service match if the port guess was wrong
            pass
        m = re.search(pat["regex"], banner, re.IGNORECASE | re.DOTALL)
        if m:
            groups = [g for g in m.groups() if g]
            if len(groups) >= 2:
                return groups[0], groups[1]
            if len(groups) == 1:
                return groups[0], ""
    return "", ""


def detect(ip: str, port_result, timeout: float = 2.0, verbose: bool = False):
    """
    Enrich a PortResult (from ports.py) in place with service/product/version/banner.

    Returns the same object for convenience.
    """
    port = port_result.port

    # 1) first-guess service name from the port number
    port_result.service = _DEFAULT_PORTS.get(str(port), "unknown")

    # 2) banner
    banner = _grab_banner(ip, port, timeout)
    port_result.banner = banner

    # 3) product + version from the banner
    if banner:
        product, version = _match_version(port_result.service, banner)
        port_result.product = product
        port_result.version = version

    if verbose:
        v = f"{port_result.product} {port_result.version}".strip()
        print(f"  [svc] {ip}:{port} -> {port_result.service} "
              f"{'(' + v + ')' if v else ''}")

    return port_result
