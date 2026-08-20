"""
html_report.py -- Generate a self-contained HTML report.

Styled to match the author's portfolio site: warm near-black background,
terracotta-orange accent, dashed borders, Playfair Display headings, DM Sans
body. The CSS is inlined so the single .html file opens anywhere; the two
Google Fonts load from a <link> (falls back to serif/sans-serif if offline).
This is the tangible artefact of the "vulnerability assessment" twist and it
films well in the demo.
"""

from __future__ import annotations

import html
from datetime import datetime


_SEV_BADGE = {
    "critical": "#e14a3b",
    "high": "#d4874d",
    "medium": "#c9962f",
    "low": "#8a9a5b",
    "info": "#8a7e70",
}

_CSS = """
:root {
  --bg: #0f0d0b; --card: #1a1714; --card-lighter: #221f1a;
  --orange: #d4874d; --orange-glow: #e8995a; --orange-dim: #a66a3a;
  --cream: #f5e6d3; --text: #c4b5a3; --text-dim: #8a7e70; --white: #faf3eb;
  --dash: 1.5px dashed rgba(212,135,77,0.22);
  --radius: 16px; --radius-sm: 10px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'DM Sans', sans-serif; background: var(--bg);
  color: var(--text); line-height: 1.7; padding: 40px 20px 72px;
}
h1, h2, h3 { font-family: 'Playfair Display', serif; color: var(--cream); font-weight: 600; }
.wrap { max-width: 980px; margin: 0 auto; }
.report-head { display: flex; align-items: center; gap: 16px; margin-bottom: 6px; }
.brand-icon {
  width: 48px; height: 48px; flex-shrink: 0;
  background: linear-gradient(135deg, var(--orange), var(--orange-dim));
  border-radius: 12px; display: flex; align-items: center; justify-content: center;
  font-family: 'Playfair Display', serif; font-weight: 700; font-size: 24px; color: var(--bg);
}
h1 { font-size: 30px; }
h1 .accent { color: var(--orange); font-style: italic; }
.sub {
  color: var(--text-dim); font-size: 13px; margin: 6px 0 30px;
  letter-spacing: .3px; padding-left: 64px;
}
.sub b { color: var(--cream); font-weight: 600; }
.cards { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 34px; }
.card {
  background: var(--card); border: var(--dash); border-radius: var(--radius);
  padding: 18px 22px; min-width: 118px; flex: 1;
}
.card .n { font-family: 'Playfair Display', serif; font-size: 30px; font-weight: 700; color: var(--cream); line-height: 1; }
.card .l {
  font-size: 11px; color: var(--text-dim); text-transform: uppercase;
  letter-spacing: 1.5px; margin-top: 8px; font-weight: 600;
}
.host {
  background: var(--card); border: var(--dash); border-left: 3px solid var(--orange);
  border-radius: var(--radius-sm); padding: 24px 26px; margin-bottom: 20px;
}
.host h2 { font-size: 20px; margin-bottom: 4px; }
.host .meta { color: var(--text-dim); font-size: 13px; margin-bottom: 16px; }
.host .meta b { color: var(--orange); font-weight: 600; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid rgba(212,135,77,0.12); vertical-align: top; }
th {
  color: var(--orange); font-weight: 600; font-size: 11px;
  text-transform: uppercase; letter-spacing: 1.5px;
}
td { color: var(--text); }
td .port { color: var(--cream); font-weight: 600; }
td .ver { color: var(--text-dim); font-style: italic; }
.badge {
  display: inline-block; padding: 3px 12px; border-radius: 50px;
  font-size: 10px; font-weight: 700; letter-spacing: .6px; color: var(--bg);
}
.vuln { font-size: 13px; margin: 8px 0; }
.vuln .cve { color: var(--orange); font-family: 'DM Sans', monospace; font-size: 12px; letter-spacing: .3px; }
.vuln .title { color: var(--cream); }
.note { color: var(--text-dim); font-size: 12px; margin-top: 2px; }
.none { color: var(--text-dim); font-style: italic; }
footer {
  color: var(--text-dim); font-size: 12px; margin-top: 40px; text-align: center;
  border-top: var(--dash); padding-top: 20px; letter-spacing: .3px;
}
footer .accent { color: var(--orange); }
"""

_FONTS = ("<link rel='preconnect' href='https://fonts.googleapis.com'>"
          "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
          "<link href='https://fonts.googleapis.com/css2?"
          "family=DM+Sans:wght@400;500;600;700&"
          "family=Playfair+Display:ital,wght@0,600;0,700;1,600&display=swap' rel='stylesheet'>")


def _badge(sev: str) -> str:
    color = _SEV_BADGE.get(sev, "#8a7e70")
    return (f'<span class="badge" style="background:{color}">'
            f'{html.escape(sev.upper())}</span>')


def generate(hosts, counts: dict, target: str, scan_type: str,
             out_path: str = "portpeek_report.html") -> str:
    """
    Write the report and return the path written.

    `hosts`  : list of Host objects (with .ports already enriched)
    `counts` : severity histogram from vulns.summarize()
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_findings = sum(counts.values())

    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>portpeek report</title>")
    parts.append(_FONTS)
    parts.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    parts.append("<div class='report-head'>")
    parts.append("<div class='brand-icon'>P</div>")
    parts.append("<h1>port<span class='accent'>peek</span> — Scan Report</h1>")
    parts.append("</div>")
    parts.append(f"<div class='sub'>Target <b>{html.escape(target)}</b> &nbsp;&middot;&nbsp; "
                 f"scan type <b>{html.escape(scan_type)}</b> &nbsp;&middot;&nbsp; "
                 f"generated {now}</div>")

    parts.append("<div class='cards'>")
    parts.append(f"<div class='card'><div class='n'>{len(hosts)}</div>"
                 f"<div class='l'>hosts</div></div>")
    parts.append(f"<div class='card'><div class='n'>{total_findings}</div>"
                 f"<div class='l'>findings</div></div>")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            parts.append(f"<div class='card'><div class='n' "
                         f"style='color:{_SEV_BADGE[sev]}'>{counts[sev]}</div>"
                         f"<div class='l'>{sev}</div></div>")
    parts.append("</div>")

    for host in hosts:
        mac = f" &nbsp;&middot;&nbsp; {html.escape(host.mac)}" if host.mac else ""
        parts.append("<div class='host'>")
        parts.append(f"<h2>{html.escape(host.ip)}</h2>")
        parts.append(f"<div class='meta'>found via <b>{html.escape(host.method or 'n/a')}</b>"
                     f"{mac} &nbsp;&middot;&nbsp; OS guess: <b>{html.escape(host.os_guess or 'unknown')}</b></div>")

        if not host.ports:
            parts.append("<div class='none'>No open ports found.</div></div>")
            continue

        parts.append("<table><thead><tr><th>Port</th><th>Service</th>"
                     "<th>Version</th><th>Findings</th></tr></thead><tbody>")
        for pr in host.ports:
            ver = html.escape(f"{pr.product} {pr.version}".strip()) or "&mdash;"
            if pr.vulns:
                cell = ""
                for v in pr.vulns:
                    cve = (f"<span class='cve'>{html.escape(v['cve'])}</span> "
                           if v.get("cve") and v["cve"] != "N/A" else "")
                    cell += (f"<div class='vuln'>{_badge(v['severity'])} {cve}"
                             f"<span class='title'>{html.escape(v['title'])}</span>"
                             f"<div class='note'>{html.escape(v['note'])}</div></div>")
            else:
                cell = "<span class='none'>none</span>"
            parts.append(f"<tr><td><span class='port'>{pr.port}/tcp</span></td>"
                         f"<td>{html.escape(pr.service)}</td>"
                         f"<td><span class='ver'>{ver}</span></td><td>{cell}</td></tr>")
        parts.append("</tbody></table></div>")

    parts.append("<footer>Generated by <span class='accent'>portpeek</span> &middot; "
                 "lab / educational use only &middot; "
                 "findings come from an offline curated table, not a live CVE feed.</footer>")
    parts.append("</div></body></html>")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    return out_path
