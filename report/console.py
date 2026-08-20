"""
console.py -- Colored terminal output for the live demo.

Uses plain ANSI escapes (no third-party dependency) and auto-disables color
when output is not a TTY (e.g. piped to a file), so logs stay clean.
"""

from __future__ import annotations

import sys

_USE_COLOR = sys.stdout.isatty()

_COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "white": "\033[37m",
}

_SEV_COLOR = {
    "critical": "magenta", "high": "red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}


def c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def banner(target: str, scan_type: str):
    print(c("=" * 60, "blue"))
    print(c("  portpeek", "bold") + c("  — modular network scanner", "dim"))
    print(f"  target: {c(target, 'cyan')}   scan: {c(scan_type, 'cyan')}")
    print(c("=" * 60, "blue"))


def host_header(host):
    print()
    mac = f"  ({host.mac})" if host.mac else ""
    print(c(f"Host {host.ip}{mac}", "bold") +
          c(f"  [found via {host.method or 'n/a'}]", "dim"))
    if host.os_guess:
        print(f"  OS guess: {c(host.os_guess, 'green')}")
    if not host.ports:
        print(c("  no open ports found", "dim"))
        return
    print(f"  {'PORT':<9}{'STATE':<9}{'SERVICE':<16}VERSION")


def port_line(pr):
    ver = f"{pr.product} {pr.version}".strip()
    line = (f"  {str(pr.port) + '/tcp':<9}"
            f"{c(pr.state, 'green'):<9}"
            f"{pr.service:<16}{ver}")
    print(line)
    for v in pr.vulns:
        tag = c(f"[{v['severity'].upper()}]", _SEV_COLOR.get(v["severity"], "white"))
        cve = f" {v['cve']}" if v.get("cve") and v["cve"] != "N/A" else ""
        print(f"      {tag}{cve} {v['title']}")


def summary(counts: dict, host_count: int):
    total = sum(counts.values())
    print()
    print(c("-" * 60, "blue"))
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            parts.append(c(f"{counts[sev]} {sev}", _SEV_COLOR.get(sev, "white")))
    findings = ", ".join(parts) if parts else c("none", "dim")
    print(f"  {host_count} host(s) scanned — {total} finding(s): {findings}")
    print(c("-" * 60, "blue"))
