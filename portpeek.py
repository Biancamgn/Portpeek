#!/usr/bin/env python3
"""
portpeek -- a modular network scanner patterned after NMAP.

Capabilities:
  * host discovery       (ARP sweep + ICMP ping sweep)
  * port scanning        (TCP connect + SYN)
  * service/version detection (banner grabbing)
  * OS fingerprinting    (TTL / TCP window heuristics)
  * vulnerability flagging  (offline version->known-issue lookup)  <-- the twist
  * HTML + colored console reporting

Lab/educational use only. Run it against machines you own or are explicitly
authorized to test (e.g. your own Metasploitable / Windows VMs on a host-only
network). Raw-socket features (SYN scan, OS fingerprint, ARP/ICMP sweep) need
root; run with sudo.

Examples:
  sudo python3 portpeek.py -t 192.168.56.0/24 --discover-only
  sudo python3 portpeek.py -t 192.168.56.101 -p 1-1024 -sV -O
  sudo python3 portpeek.py -t 192.168.56.0/24 -p 21,22,80,445 -sV -O --html out.html
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from scanner import discovery, ports, services, fingerprint, vulns
from report import console, html_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portpeek",
        description="Modular network scanner (host discovery, port scan, "
                    "version detection, OS fingerprint, vuln flagging).",
        epilog="Lab use only. Scan only systems you are authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target", required=True,
                   help="target IP, CIDR, or comma list (e.g. 192.168.56.0/24)")
    p.add_argument("-p", "--ports", default=None,
                   help="ports to scan: '22', '1-1024', '22,80,443'. "
                        "Default: a curated common set.")

    # discovery mode
    p.add_argument("--discovery", choices=["auto", "arp", "icmp"], default="auto",
                   help="host discovery method (default: auto = ARP then ICMP)")
    p.add_argument("--discover-only", action="store_true",
                   help="stop after host discovery (a pure ping/ARP sweep)")

    # scan type (NMAP-ish flags)
    p.add_argument("-sT", dest="scan_type", action="store_const", const="connect",
                   help="TCP connect scan (no root needed)")
    p.add_argument("-sS", dest="scan_type", action="store_const", const="syn",
                   help="SYN (half-open) scan (needs root)")
    p.set_defaults(scan_type="auto")

    # feature toggles
    p.add_argument("-sV", "--version-detect", action="store_true",
                   help="detect service/version via banner grabbing")
    p.add_argument("-O", "--os-detect", action="store_true",
                   help="OS fingerprinting (TTL/window heuristic)")
    p.add_argument("--no-vulns", action="store_true",
                   help="skip the vulnerability-flagging step")

    # tuning + output
    p.add_argument("--timeout", type=float, default=1.5,
                   help="per-probe timeout in seconds (default 1.5)")
    p.add_argument("--workers", type=int, default=100,
                   help="concurrent port-scan threads (default 100)")
    p.add_argument("--html", metavar="FILE", default=None,
                   help="write an HTML report to FILE")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="verbose per-probe output")
    return p


def _warn_if_not_root(args) -> None:
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    needs_root = args.scan_type == "syn" or args.os_detect or \
        args.discovery in ("arp", "icmp", "auto")
    if needs_root and not is_root:
        print(console.c(
            "[!] Not running as root. ARP/ICMP sweep, SYN scan and OS "
            "fingerprint need raw sockets — some features will degrade or "
            "fail. Re-run with sudo for full functionality.\n", "yellow"),
            file=sys.stderr)


def run(args) -> int:
    console.banner(args.target, args.scan_type)
    _warn_if_not_root(args)

    # -- 1. host discovery -------------------------------------------------
    try:
        hosts = discovery.discover(args.target, mode=args.discovery,
                                   timeout=int(args.timeout) or 1,
                                   verbose=args.verbose)
    except (PermissionError, ValueError) as exc:
        print(console.c(f"[x] discovery failed: {exc}", "red"), file=sys.stderr)
        return 1

    if not hosts:
        print(console.c("\nNo live hosts found.", "yellow"))
        return 0

    print(console.c(f"\n{len(hosts)} host(s) up.", "green"))

    if args.discover_only:
        for h in hosts:
            mac = f"  ({h.mac})" if h.mac else ""
            print(f"  {h.ip}{mac}  [{h.method}]")
        return 0

    port_list = None
    if args.ports:
        try:
            port_list = ports.parse_ports(args.ports)
        except ValueError as exc:
            print(console.c(f"[x] {exc}", "red"), file=sys.stderr)
            return 1

    # -- 2..5 per-host pipeline -------------------------------------------
    for host in hosts:
        host.ports = ports.scan_ports(
            host.ip, port_list, scan_type=args.scan_type,
            timeout=args.timeout, workers=args.workers, verbose=args.verbose)

        if args.version_detect:
            for pr in host.ports:
                services.detect(host.ip, pr, timeout=args.timeout,
                                verbose=args.verbose)

        if not args.no_vulns:
            for pr in host.ports:
                vulns.check(pr)

        if args.os_detect:
            first_open = host.ports[0].port if host.ports else None
            host.os_guess, _conf = fingerprint.fingerprint(
                host.ip, first_open, timeout=args.timeout, verbose=args.verbose)

        console.host_header(host)
        for pr in host.ports:
            console.port_line(pr)

    # -- 6. reporting ------------------------------------------------------
    counts = vulns.summarize(hosts)
    console.summary(counts, len(hosts))

    if args.html:
        path = html_report.generate(hosts, counts, args.target,
                                     args.scan_type, args.html)
        print(console.c(f"\n[+] HTML report written to {path}", "green"))

    return 0


def main() -> int:
    args = build_parser().parse_args()
    start = time.time()
    try:
        code = run(args)
    except KeyboardInterrupt:
        print(console.c("\n[!] interrupted by user", "yellow"))
        return 130
    print(console.c(f"\ndone in {time.time() - start:.1f}s", "dim"))
    return code


if __name__ == "__main__":
    sys.exit(main())
