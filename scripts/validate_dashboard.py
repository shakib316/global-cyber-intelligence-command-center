#!/usr/bin/env python3
"""Static dashboard and latest-intelligence integrity checks."""
import json, re, subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
html = (root / "index.html").read_text(encoding="utf-8")
required = ["criticalVulnList", "prepareBriefing", "businessList", "queryGrid", "loadQueries"]
missing = [x for x in required if x not in html]
if missing:
    raise SystemExit("Dashboard missing required UI features: " + ", ".join(missing))

scripts = re.findall(r"<script>([\\s\\S]*?)</script>", html, re.I)
if not scripts:
    raise SystemExit("No inline dashboard JavaScript found")
with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as f:
    f.write(scripts[-1]); f.flush()
    result = subprocess.run(["node", "--check", f.name], capture_output=True, text=True)
    if result.returncode:
        raise SystemExit("Dashboard JavaScript syntax error:\\n" + result.stderr)

pointer_path = root / "intel/latest.json"
if not pointer_path.exists():
    raise SystemExit("intel/latest.json is missing")
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
snapshot_path = root / "intel" / pointer["snapshot"]
if not snapshot_path.exists():
    raise SystemExit("Latest intelligence snapshot is missing: " + str(snapshot_path))
data = json.loads(snapshot_path.read_text(encoding="utf-8"))
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
print("Dashboard checks passed.")
print("Business developments:", len(data["business_items"]))
print("Business feeds:", len(business_sources))
print("Threat items:", len(data.get("items", [])))
print("Source health:", data.get("successful_sources", 0), "/", data.get("total_sources", 0))
