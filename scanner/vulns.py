"""
vulns.py -- Flag outdated / vulnerable service versions (the creativity twist).

This is what turns the scanner from "an NMAP clone" into a mini
vulnerability-assessment tool. It does NOT exploit anything; it only compares
the product+version strings that services.py detected against a small,
hand-curated offline table (data/vuln_db.json) and reports matches.

Because the table is offline and curated, there is no network dependency and
the behaviour is fully reproducible for a demo.
"""

from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data" / "vuln_db.json"

# Ordering so we can sort findings worst-first in the report.
SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


def _load_db() -> list[dict]:
    with open(_DATA, "r", encoding="utf-8") as fh:
        return json.load(fh).get("entries", [])


_ENTRIES = _load_db()


def check(port_result) -> list[dict]:
    """
    Given an enriched PortResult, return a list of matching vuln dicts.

    The needle we match on is "<product> <version> <service>" lowercased, so a
    table entry like "vsftpd 2.3.4" matches, and a service-only entry like
    "telnet" also matches on the service name alone.
    """
    haystack = " ".join(
        filter(None, [port_result.product, port_result.version,
                      port_result.service])
    ).lower()

    findings: list[dict] = []
    for entry in _ENTRIES:
        if entry["match"].lower() in haystack:
            findings.append(entry)

    findings.sort(key=lambda e: SEVERITY_ORDER.get(e["severity"], 99))
    port_result.vulns = findings
    return findings


def summarize(hosts) -> dict:
    """
    Roll up a severity histogram across every scanned host, for the report
    header and the console summary line.
    """
    counts = {k: 0 for k in SEVERITY_ORDER}
    for host in hosts:
        for pr in host.ports:
            for v in pr.vulns:
                counts[v["severity"]] = counts.get(v["severity"], 0) + 1
    return counts
