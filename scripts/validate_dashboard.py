#!/usr/bin/env python3
"""Static dashboard and latest-intelligence integrity checks."""
import ast, importlib.util, json, re, subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
html = (root / "index.html").read_text(encoding="utf-8")
required = ["criticalVulnList", "prepareBriefing", "businessList", "queryGrid", "loadQueries", "reportPicker", "loadReportPath", "threatPrev", "businessPrev", "kevPrev", "cisa_kev_catalog", "CVERecord?id=", "kevStatus", "queriesLoaded", "const groups={}", "globalSearchPanel", "globalSearch", "globalScope", "kevSearch", "kevVendor", "kevDueFilter", "priorityFilter", "v.vulnerabilityName", "function globalSearch", "function filteredKev", "const remediationBlock=", "function relatedFor", "function renderWatchlist", "function matchAssets", "function renderIOC", "function compareSnapshots", "function copyExecutiveDigest", "function renderReadiness", "oldestReport", "intel\\/daily", "remediation_guidance", "No specific fix identified in retrieved source text", "function kevHtml", "function itemHtml", "function businessCard", "function businessSignificance", "Article text retrieved", "What to verify next", "businessDetail", "businessClear", "knownRansomwareCampaignUse", "Evidence "]
missing = [x for x in required if x not in html]
if missing:
    raise SystemExit("Dashboard missing required UI features: " + ", ".join(missing))

ids = re.findall(r'\bid="([^"]+)"', html)
duplicates = sorted({x for x in ids if ids.count(x) > 1})
if duplicates:
    raise SystemExit("Dashboard contains duplicate HTML IDs: " + ", ".join(duplicates))
if 'function itemHtml(x)' not in html or 'remediationBlock(x,"threat")' not in html:
    raise SystemExit("Threat cards do not show adjacent remediation guidance")
if 'name==="briefing"' not in html or 'loadReportPath(currentReportPath)' not in html:
    raise SystemExit("Full daily report is not lazy-loaded on briefing navigation")
if len(re.findall(r"function itemHtml\(x\)", html)) != 1:
    raise SystemExit("Dashboard must have exactly one threat-card renderer")
if 'descriptionBlock("What to verify next",businessSignificance(x))' not in html or 'remediationBlock(x,"business")' in html:
    raise SystemExit("Business cards must show useful verification context without irrelevant vulnerability remediation")
if "function cleanCopy(value)" not in html or "Compact reading layout" not in html:
    raise SystemExit("Dashboard description cleanup or compact reading styles are missing")
if 'function kevHtml(v)' not in html or 'v.requiredAction' not in html:
    raise SystemExit("KEV remediation column is missing")

scripts = re.findall(r"<script>([\s\S]*?)</script>", html, re.I)
if not scripts:
    raise SystemExit("No inline dashboard JavaScript found")
with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as f:
    f.write(scripts[-1]); f.flush()
    result = subprocess.run(["node", "--check", f.name], capture_output=True, text=True)
    if result.returncode:
        raise SystemExit("Dashboard JavaScript syntax error:\\n" + result.stderr)

collector_path = root / "scripts/collect_threat_intel.py"
if not collector_path.exists():
    raise SystemExit("Threat intelligence collector is missing")
collector_source = collector_path.read_text(encoding="utf-8")
ast.parse(collector_source, filename=str(collector_path))
spec = importlib.util.spec_from_file_location("gci_collector", collector_path)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
generic_fix = "Apply mitigations in accordance with vendor instructions for affected systems."
if collector.extract_specific_remediation(generic_fix):
    raise SystemExit("Generic vendor boilerplate was incorrectly accepted as a fix")
if collector.extract_specific_remediation("Apply patches to affected systems as soon as possible."):
    raise SystemExit("Non-specific patch advice was incorrectly accepted as a fix")
specific_fixes = [
    "Upgrade Example Product to version 4.2.1 to remediate the vulnerability.",
    "Disable SMBv1 on affected Windows hosts until the patch is installed.",
    "Install security update KB5031234 on affected endpoints.",
]
for example in specific_fixes:
    if not collector.extract_specific_remediation(example):
        raise SystemExit("A concrete remediation example was not extracted: " + example)

for marker in ("def extract_specific_remediation", "def enrich_records", "class ArticleText", '"details"', '"remediation_guidance"', '"remediation_status"', '"related_sources"', '"attack_techniques"', "CyberScoop", "SecurityWeek", "Dark Reading", "The Record", "TechCrunch Security", "canonical_url"):
    if marker not in collector_source:
        raise SystemExit("Collector missing source enrichment/correlation capability: " + marker)

pointer_path = root / "intel/latest.json"
if not pointer_path.exists():
    raise SystemExit("intel/latest.json is missing")
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
daily_report_path = root / "intel" / pointer.get("report", "")
if not daily_report_path.exists():
    raise SystemExit("Latest daily intelligence report is missing")
daily_report = daily_report_path.read_text(encoding="utf-8")
if "Fix / remediation:" not in daily_report or "Business background / implications:" not in daily_report:
    raise SystemExit("Daily report is missing adjacent threat remediation or business context")
snapshot_path = root / "intel" / pointer["snapshot"]
if not snapshot_path.exists():
    raise SystemExit("Latest intelligence snapshot is missing: " + str(snapshot_path))
data = json.loads(snapshot_path.read_text(encoding="utf-8"))
kev = data.get("cisa_kev_catalog", [])
items = data.get("items", [])
business_items = data.get("business_items", [])
if not kev:
    raise SystemExit("CISA KEV catalogue is empty")
kev_ids = [x.get("cveID") for x in kev]
if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(x or "")) for x in kev_ids):
    raise SystemExit("CISA KEV contains a missing or malformed CVE identifier")
if len(kev_ids) != len(set(kev_ids)):
    raise SystemExit("CISA KEV contains duplicate CVE identifiers")
missing_kev_titles = [x.get("cveID") for x in kev if not x.get("vulnerabilityName")]
if missing_kev_titles:
    raise SystemExit("CISA KEV records missing vulnerabilityName: " + ", ".join(missing_kev_titles[:10]))
for label, records in (("threat intelligence", items), ("business intelligence", business_items)):
    missing = [i for i, x in enumerate(records) if not x.get("title") or not x.get("url") or not str(x.get("url")).startswith("https://")]
    if missing:
        raise SystemExit(f"{label} has {len(missing)} records missing a title or safe HTTPS source URL")
for label, records in (("threat intelligence", items), ("business intelligence", business_items)):
    missing_details = sum(not x.get("details") for x in records)
    if missing_details:
        raise SystemExit(f"{label} has {missing_details} records without an in-page detail field")
if any(not x.get("remediation_status") for x in items):
    raise SystemExit("Threat intelligence records are missing explicit remediation status")
if not isinstance(data.get("ioc_candidates", []), list):
    raise SystemExit("IOC correlation candidates must be a list")
if not isinstance(data.get("business_items"), list):
    raise SystemExit("Latest snapshot has no business_items array")
business_sources = [x for x in data.get("source_health", []) if x.get("stream") == "business"]
if not business_sources:
    raise SystemExit("No cyber-business sources are represented in source_health")
report_path = root / "reports" / pointer["date_utc"][:4] / pointer["date_utc"][5:7] / (pointer["date_utc"][8:10] + ".md")
if report_path.exists():
    report = report_path.read_text(encoding="utf-8")
    if "Sentinel KQL" in report and "prepareBriefing" not in html:
        raise SystemExit("Report contains query section but dashboard lacks inline-query renderer")
print("Dashboard checks passed: unique DOM IDs, latest/newer/older/oldest date navigation, historical report discovery, global search, filters, detailed threat/business cards, adjacent remediation, full KEV actions, watchlist, asset matcher, IOC correlation, ATT&CK/readiness, executive digest, JavaScript and collector syntax.")
print("Full CISA KEV records:", len(kev), "| titles present:", len(kev), "| duplicate CVEs:", len(kev_ids) - len(set(kev_ids)))
print("Business developments:", len(data["business_items"]))
print("Business feeds:", len(business_sources))
print("Threat items:", len(data.get("items", [])))
print("Source health:", data.get("successful_sources", 0), "/", data.get("total_sources", 0))
