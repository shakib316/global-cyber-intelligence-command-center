#!/usr/bin/env python3
"""Static dashboard and latest-intelligence integrity checks."""
import ast, importlib.util, json, re, subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
html = (root / "index.html").read_text(encoding="utf-8")
required = ["criticalVulnList", "prepareBriefing", "businessList", "queryGrid", "loadQueries", "reportPicker", "loadReportPath", "threatPrev", "businessPrev", "kevPrev", "cisa_kev_catalog", "CVERecord?id=", "kevStatus", "queriesLoaded", "const groups={}", "globalSearchPanel", "globalSearch", "globalScope", "kevSearch", "kevVendor", "kevDueFilter", "priorityFilter", "v.vulnerabilityName", "function globalSearch", "function filteredKev", "const remediationBlock=", "function relatedFor", "function renderWatchlist", "function matchAssets", "function renderIOC", "function compareSnapshots", "function copyExecutiveDigest", "function renderReadiness", "oldestReport", "intel\\/daily", "remediation_guidance", "No specific fix identified in retrieved source text", "function kevHtml", "function kevAction", "function itemHtml", "function businessCard", "function businessSignificance", "vendor_remediation", "LINKED VENDOR ADVISORY", "Article text retrieved", "What to verify next", "businessDetail", "businessClear", "knownRansomwareCampaignUse", "Evidence "]
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
if 'function kevAction(v)' not in html or 'const a=kevAction(v)' not in html or 'kevStatus(v),a.specific?"green":"amber"' not in html:
    raise SystemExit("Critical watch and KEV previews must use the shared specific-remediation guard")
critical_start = html.find('$("criticalVulnList").innerHTML=')
critical_end = html.find('$("kevPreview").innerHTML=', critical_start)
if critical_start < 0 or critical_end < 0 or 'kevAction(v)' not in html[critical_start:critical_end] or 'v.requiredAction' in html[critical_start:critical_end]:
    raise SystemExit("Critical vulnerability watch bypasses the shared KEV remediation guard")

asset_start = html.find("function matchAssets()")
asset_end = html.find("async function compareSnapshots()", asset_start)
if asset_start < 0 or asset_end < 0 or "kevAction(v).text" not in html[asset_start:asset_end] or "v.requiredAction" in html[asset_start:asset_end]:
    raise SystemExit("Asset exposure matcher bypasses the shared KEV remediation guard")
digest_start = html.find("async function copyExecutiveDigest()")
digest_end = html.find("function renderOps()", digest_start)
if digest_start < 0 or digest_end < 0 or "kevAction(x).text" not in html[digest_start:digest_end] or "x.requiredAction" in html[digest_start:digest_end]:
    raise SystemExit("Executive digest bypasses the shared KEV remediation guard")
preview_end = html.find("renderKev();", critical_end)
if critical_end < 0 or preview_end < 0 or 'kevAction(v)' not in html[critical_end:preview_end] or 'v.requiredAction' in html[critical_end:preview_end]:
    raise SystemExit("Recent KEV preview bypasses the shared KEV remediation guard")

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

daily_workflow_path = root / ".github/workflows/daily-threat-intel.yml"
daily_workflow = daily_workflow_path.read_text(encoding="utf-8")
for required_step in ("  deploy:", "    needs: collect", "pages: write", "id-token: write", "actions/upload-pages-artifact@v3", "actions/deploy-pages@v4"):
    if required_step not in daily_workflow:
        raise SystemExit("Daily collection workflow does not publish updated Pages content: " + required_step)
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

# CVEs must be re-extracted after full-page enrichment, including identifiers of variable length.
cve_example = "Article text: affected components include CVE-2026-129538, CVE-2026-95325 and CVE-2026-100000001."
if collector.extract_cves(cve_example) != ["CVE-2026-100000001", "CVE-2026-129538", "CVE-2026-95325"]:
    raise SystemExit("CVE extraction missed variable-length IDs in full article text")
if "item.get(\"details\")" not in collector_source or "CVE extraction scope" in collector_source:
    # The collector must derive the final CVE list from article details after enrichment.
    if 'item["cves"]=extract_cves(item.get("title"),item.get("summary"),item.get("details")' not in collector_source:
        raise SystemExit("CVE extraction is not performed after article enrichment")

if collector.deal_status("CrowdStrike-Zscaler acquisition talks reported by multiple outlets") != "Rumoured":
    raise SystemExit("Reported acquisition discussions must remain Rumoured")
if collector.deal_status("Company signs a definitive agreement to acquire Example Corp") != "Signed":
    raise SystemExit("A definitive acquisition agreement must be classified Signed")
if collector.deal_status("Company completed the acquisition of Example Corp") != "Completed":
    raise SystemExit("A completed acquisition must be classified Completed")
if collector.business_category("FBI launches Operation Winter Shield to arrest cybercriminals") != "Law enforcement & operations":
    raise SystemExit("Law-enforcement operations must not be classified as product launches")

noun_only = "According to Microsoft, the issue is related to the KB5132043 Windows hotpatch update."
if collector.extract_specific_remediation(noun_only):
    raise SystemExit("A product/update noun was incorrectly accepted as remediation")

false_positive_fixes = [
    "kernel: scsi: scsi_debug: Sanity check block descriptor length in resp_mode_select() (CVE-2021-47576)",
    "kernel: s390/cpum_sf: Handle CPU hotplug remove during sampling (CVE-2024-57849)",
    "Although BOD 26-04 targets only federal agencies, CISA urged all network defenders to prioritize patching this flaw.",
]
for candidate in false_positive_fixes:
    if collector.extract_specific_remediation(candidate):
        raise SystemExit("Non-actionable description was incorrectly accepted as remediation: " + candidate)
workaround_text = "In the absence of an official patch, organizations should discontinue its use and replace it with an actively supported alternative such as follows.\nASP.NET WebForms Page.ViewStateUserKey combined with MAC-verified/encrypted ViewState on postback forms."
workaround = collector.extract_specific_remediation(workaround_text)
if not workaround or not any("ViewStateUserKey" in x for x in workaround):
    raise SystemExit("Concrete workaround details were lost during remediation extraction")
kev_generic = {"requiredAction": "Apply mitigations in accordance with vendor instructions for affected systems."}
kev_text = collector.kev_remediation_text(kev_generic)
if "Apply mitigations in accordance with vendor instructions" in kev_text or "No product/version-specific" not in kev_text:
    raise SystemExit("Daily KEV report still emits generic CISA remediation boilerplate")
kev_specific = {"requiredAction": "Upgrade Example Product to version 4.2.1 to remediate the vulnerability."}
if "version 4.2.1" not in collector.kev_remediation_text(kev_specific):
    raise SystemExit("Daily KEV report dropped a concrete source-backed remediation")

for promo in (
    "Discover why SHA pinning alone isn't enough and learn how to close hidden security gaps.",
    "Learn what 6,000 real-world attacks reveal about MFA weaknesses.",
):
    if not collector.is_promotional_text(promo):
        raise SystemExit("Promotional content was not filtered from article enrichment: " + promo)
if collector.is_promotional_text("Researchers discovered why the vulnerability occurs in the parser."):
    raise SystemExit("Legitimate technical reporting was incorrectly classified as promotional")

if not collector.is_stock_market_noise("Why Is Palo Alto Networks Stock Falling?"):
    raise SystemExit("Stock-price-only business noise was not filtered")
if collector.is_stock_market_noise("Palo Alto Networks announces acquisition of Applied Compute"):
    raise SystemExit("A material cybersecurity company transaction was incorrectly filtered")

portal_fix = "While a fix is not yet available, the vendor has shared a temporary workaround in its support portal, which requires signing in."
portal_status = collector.re.search(r"(?:a )?(?:security )?fix is not yet available|in the absence of an official patch", portal_fix, collector.re.I)
portal_access = collector.re.search(r"temporary workaround.{0,240}(?:signing in|sign in|support portal|customer portal)", portal_fix, collector.re.I)
if not portal_status or not portal_access:
    raise SystemExit("Portal-gated workaround state is not detected")

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
for item in items:
    if item.get("cve_extraction_scope"):
        expected = set(collector.extract_cves(item.get("title"), item.get("summary"), item.get("details"),
            " ".join(fix for ref in item.get("vendor_remediation", []) for fix in ref.get("guidance", []))))
        actual = set(item.get("cves", []))
        if expected - actual:
            raise SystemExit("CVE list omits IDs present in enriched evidence for: " + str(item.get("title", "untitled")))
for item in business_items:
    if item.get("business_context_quality") == "limited" and item.get("enrichment_status") == "enriched":
        raise SystemExit("Headline-only business content is incorrectly labelled enriched: " + str(item.get("title", "untitled")))
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
report_date = pointer.get("date_ist", pointer["date_utc"])
report_path = root / "reports" / report_date[:4] / report_date[5:7] / (report_date[8:10] + ".md")
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
