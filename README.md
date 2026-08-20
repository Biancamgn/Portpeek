# portpeek

A modular command-line network scanner patterned after NMAP, written in Python
with scapy. Built for NSSECU2 and intended for use only
against machines you own or are explicitly authorized to test (e.g. your own
Metasploitable and Windows VMs on a host-only network).

## Capabilities

| Requirement | Module | Technique |

| Host discovery (ping sweep) | `scanner/discovery.py` | ARP sweep (L2) + ICMP echo sweep (L3) |
| Port scanning | `scanner/ports.py` | TCP connect scan + SYN (half-open) scan |
| Service / version detection | `scanner/services.py` | banner grabbing + regex version extraction |
| OS fingerprinting | `scanner/fingerprint.py` | TTL + TCP window-size heuristics |
| **Vulnerability flagging (twist)** | `scanner/vulns.py` | offline version → known-issue lookup |
| Reporting | `report/console.py`, `report/html_report.py` | colored console + self-contained HTML |

## Project layout

```
portpeek/
├── portpeek.py            # CLI entry point / orchestration
├── scanner/
│   ├── discovery.py      # host discovery
│   ├── ports.py          # port scanning
│   ├── services.py       # service + version detection
│   ├── fingerprint.py    # OS fingerprinting
│   └── vulns.py          # vulnerability flagging (twist)
├── report/
│   ├── console.py        # colored terminal output
│   └── html_report.py    # HTML report generator
├── data/
│   ├── services.json     # port→service map + banner→version regexes
│   └── vuln_db.json      # curated offline vulnerability table
├── requirements.txt
└── README.md
```

## Install

On Kali, scapy is usually preinstalled. Otherwise:

```bash
pip install -r requirements.txt
```

## Usage

Raw-socket features (ARP/ICMP sweep, SYN scan, OS fingerprint) need root — run
with `sudo`.

```bash
# Pure host discovery (ARP/ping sweep) across a subnet
sudo python3 portpeek.py -t 192.168.56.0/24 --discover-only

# Full scan of one host: SYN scan + version + OS + vuln flag + HTML report
sudo python3 portpeek.py -t 192.168.56.101 -p 1-1024 -sS -sV -O --html report.html

# Connect scan (no root) of specific ports
python3 portpeek.py -t 192.168.56.101 -p 21,22,80,445 -sT -sV
```

### Key flags

| Flag | Meaning |
|---|---|
| `-t, --target` | IP, CIDR, or comma-separated list (required) |
| `-p, --ports` | `22`, `1-1024`, or `22,80,443` (default: common set) |
| `--discovery {auto,arp,icmp}` | host-discovery method |
| `--discover-only` | stop after the sweep |
| `-sT` / `-sS` | TCP connect scan / SYN scan |
| `-sV` | service + version detection |
| `-O` | OS fingerprinting |
| `--no-vulns` | skip vulnerability flagging |
| `--html FILE` | write an HTML report |
| `-v` | verbose |

## How the vulnerability twist works

After version detection, each detected `product + version` string is matched
(case-insensitive substring) against `data/vuln_db.json`, a small curated table
tuned to the lab targets. Matches are attached to the port, rolled up into a
severity histogram, and rendered in both the console summary and the HTML
report. It is **not** a live CVE feed — it is offline and reproducible by
design, which keeps the demo deterministic.

## Limitations

* OS fingerprinting is a labeled heuristic, not NMAP's full fingerprint stack.
* The vuln table is small and curated for the lab, not exhaustive.
* SYN scan and OS detection require root and a network that permits raw packets.

## Legal / ethical note

For educational use in an isolated lab against systems you control or are
authorized to assess. Do not scan networks you do not own or have permission
to test.
