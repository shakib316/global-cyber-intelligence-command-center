#!/usr/bin/env python3
"""Collect public CISA KEV and URLhaus feeds; emit dated evidence and draft KQL.

This script intentionally does not infer actor attribution or generate unverified IOCs.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
UTC_NOW = dt.datetime.now(dt.timezone.utc)
DAY = UTC_NOW.date().isoformat()
STAMP = UTC_NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
TIMEOUT = 25
USER_AGENT = "GCI-DailyThreatIntel/1.0 (+https://github.com/shakib316/global-cyber-intelligence-command-center)"
SOURCES = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "urlhaus_recent": "https://urlhaus.abuse.ch/downloads/csv_recent/",
}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} from {url}")
        return response.read()


def clean_url_indicator(raw: str) -> tuple[str, str] | None:
    value = raw.strip().strip('"')
    if not value or value.startswith("#"):
        return None
    parsed = urlparse(value if "://" in value else "http://" + value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        kind = "ip"
    except ValueError:
        if "." not in host or len(host) > 253:
            return None
        kind = "url_or_domain"
    return value.lower(), kind


def main() -> int:
    errors: list[str] = []
    kev: dict = {}
    urlhaus_rows: list[dict] = []

    try:
        kev = json.loads(fetch(SOURCES["cisa_kev"]).decode("utf-8"))
    except Exception as exc:
        errors.append(f"CISA KEV collection failed: {type(exc).__name__}: {exc}")

    try:
        raw_csv = fetch(SOURCES["urlhaus_recent"]).decode("utf-8", errors="replace")
        for row in csv.reader(line for line in raw_csv.splitlines() if line and not line.startswith("#")):
            if len(row) < 8:
                continue
            parsed = clean_url_indicator(row[2])
            if not parsed:
                continue
            indicator, kind = parsed
            urlhaus_rows.append({
                "indicator": indicator,
                "type": kind,
                "date_added": row[1].strip(),
                "status": row[3].strip(),
                "threat": row[5].strip(),
                "tags": [x.strip() for x in row[6].split(",") if x.strip()],
                "source": "URLhaus",
                "source_url": SOURCES["urlhaus_recent"],
                "retrieved_at": STAMP,
                "confidence": "Feed-listed; validate in local telemetry",
            })
    except Exception as exc:
        errors.append(f"URLhaus collection failed: {type(exc).__name__}: {exc}")

    # Keep only the newest 500 unique URL indicators to keep the generated hunt manageable.
    dedup: dict[str, dict] = {}
    for item in urlhaus_rows:
        dedup[item["indicator"]] = item
    indicators = sorted(dedup.values(), key=lambda x: x["date_added"], reverse=True)[:500]

    if not kev and not indicators:
        print("No feed succeeded; refusing to publish an empty success snapshot.")
        print("\n".join(errors))
        return 1

    vulnerabilities = kev.get("vulnerabilities", []) if kev else []
    recent_kev = [
        v for v in vulnerabilities
        if v.get("dateAdded", "") >= (UTC_NOW.date() - dt.timedelta(days=7)).isoformat()
    ]
    recent_kev.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

    payload = {
        "report_date_utc": DAY,
        "retrieved_at": STAMP,
        "sources": SOURCES,
        "collection_status": {
            "cisa_kev": "success" if kev else "failed",
            "urlhaus_recent": "success" if urlhaus_rows else ("empty_or_failed"),
        },
        "errors": errors,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "cisa_kev_catalog_count": len(vulnerabilities),
        "cisa_kev_added_last_7_days": recent_kev,
        "notes": [
            "CISA KEV entries indicate known exploitation, not necessarily a currently active campaign against your environment.",
            "URLhaus indicators are feed-listed URLs/domains/IPs; matching them is a lead, not proof of compromise.",
            "Validate indicator age, relevance, reputation and local telemetry before response.",
        ],
    }

    dated = Path("intel") / "daily" / DAY[:4] / DAY[5:7] / f"{DAY[8:10]}.md"
    json_path = Path("intel") / "indicators" / DAY[:4] / DAY[5:7] / f"{DAY[8:10]}.json"
    query_path = Path("detection-queries") / "generated" / DAY[:4] / DAY[5:7] / f"urlhaus_ioc_hunt_{DAY}.kql"
    for path in (dated, json_path, query_path):
        (ROOT / path).parent.mkdir(parents=True, exist_ok=True)

    (ROOT / json_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        f"# Daily Threat Intelligence Snapshot — {DAY} (UTC)",
        "",
        f"- Retrieved: {STAMP}",
        f"- CISA KEV catalog entries: {len(vulnerabilities)}",
        f"- KEV entries added in last 7 days: {len(recent_kev)}",
        f"- URLhaus unique indicators collected: {len(indicators)}",
        "",
        "## Feed health",
        f"- CISA KEV: {'success' if kev else 'FAILED'}",
        f"- URLhaus: {'success' if urlhaus_rows else 'empty or FAILED'}",
        "",
        "## CISA Known Exploited Vulnerabilities — recent additions",
        "",
    ]
    if recent_kev:
        for v in recent_kev[:30]:
            lines.append(f"- **{v.get('cveID','CVE unavailable')}** — {v.get('vulnerabilityName','Name unavailable')} | added {v.get('dateAdded','unknown')} | vendor: {v.get('vendorProject','unknown')} | product: {v.get('product','unknown')} | [CISA record]({v.get('notes','')})")
    else:
        lines.append("- No KEV additions in the last seven days were returned (or the KEV feed was unavailable).")
    lines += [
        "",
        "## URLhaus indicator feed",
        "",
        "This feed is a rolling malicious-URL feed, not a complete inventory of current attacker infrastructure. Indicator matches require investigation.",
        "",
        "| Type | Indicator | Date added | Threat |",
        "|---|---|---|---|",
    ]
    for item in indicators[:50]:
        safe = item["indicator"].replace("|", "%7C")
        lines.append(f"| {item['type']} | `{safe}` | {item['date_added']} | {item['threat'] or 'unspecified'} |")
    lines += [
        "",
        "## Detection engineering",
        "",
        f"- Generated draft: [URLhaus IOC hunt]({os.path.relpath(query_path, dated.parent)})",
        "- Maturity: **Draft**. This query uses Defender XDR tables and must be checked against the tenant schema and tested before operational use.",
        "- No query is automatically promoted to production.",
        "",
        "## Collection errors",
        "",
    ]
    lines.extend([f"- {e}" for e in errors] or ["- None."])
    lines += [
        "",
        "## Interpretation and limitations",
        "",
        "- CISA KEV is a vulnerability exploitation-priority source; it does not provide network IOCs.",
        "- URLhaus provides malicious URL observations; feed inclusion alone does not prove an endpoint was compromised.",
        "- This automated snapshot is a feed-driven supplement, not a replacement for the full human-reviewed threat radar, CERT-In advisories, vendor research, ransomware reporting or campaign analysis.",
        "- Collection uses UTC dates. Convert timestamps to IST for operational triage.",
        "",
        f"Raw evidence: [JSON snapshot]({os.path.relpath(json_path, dated.parent)}).",
    ]
    (ROOT / dated).write_text("\n".join(lines) + "\n", encoding="utf-8")

    urls = [x["indicator"] for x in indicators if x["type"] == "url_or_domain"]
    ips = [x["indicator"] for x in indicators if x["type"] == "ip"]
    # KQL strings are JSON-escaped, which is compatible with KQL quoted string literals.
    url_values = ",\n    ".join(json.dumps(x) for x in urls[:300]) or '"NO_INDICATORS_COLLECTED"'
    ip_values = ",\n    ".join(json.dumps(x) for x in ips[:300]) or '"NO_INDICATORS_COLLECTED"'
    query = f'''// ID: GCI-KQL-IOC-{DAY.replace("-", "")}
// Title: Daily URLhaus IOC network hunt — {DAY}
// Platform: Microsoft Sentinel / Defender XDR
// Type: Threat-intelligence hunt (not an auto-block rule)
// Data source: DeviceNetworkEvents
// Required fields: Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
// Prerequisites: Defender for Endpoint network telemetry; feed snapshot reviewed for freshness
// Maturity: Draft — generated from feed; schema and syntax not validated
// Source: URLhaus recent URL feed; snapshot intel/indicators/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.json
// False positives: Shared hosting, sinkholes, stale/reassigned infrastructure, benign redirects
// Tuning: Confirm indicator age and ownership; add approved exclusions; retain source and first-seen context
// Owner: Detection Engineering
// Last reviewed: {DAY}
// Review by: { (UTC_NOW.date() + dt.timedelta(days=7)).isoformat() }

let UrlIndicators = dynamic([
    {url_values}
]);
let IpIndicators = dynamic([
    {ip_values}
]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| extend NormalizedRemoteUrl = tolower(RemoteUrl), NormalizedRemoteIP = tostring(RemoteIP)
| where (isnotempty(NormalizedRemoteUrl) and NormalizedRemoteUrl has_any (UrlIndicators))
    or (isnotempty(NormalizedRemoteIP) and NormalizedRemoteIP in (IpIndicators))
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
'''
    (ROOT / query_path).write_text(query, encoding="utf-8")
    print(f"Wrote {dated}, {json_path}, {query_path}")
    print(f"Collected {len(indicators)} URLhaus indicators and {len(recent_kev)} recent KEV additions.")
    if errors:
        print("Partial collection; see report errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
