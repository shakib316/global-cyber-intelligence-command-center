#!/usr/bin/env python3
"""Static quality gates for detection queries; this does not parse or run KQL."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
QUERY_ROOT = ROOT / "detection-queries"
REQUIRED = ("ID:", "Title:", "Platform:", "Type:", "Data source:",
            "Maturity:", "False positives:", "Tuning:")
MATURITY = {"Draft", "Schema-checked", "Syntax-validated",
            "Lab-tested", "Production-approved", "Retired"}
ID_RE = re.compile(r"^//\s*ID:\s*([A-Z0-9][A-Z0-9-]+)\s*$", re.M)
MATURITY_RE = re.compile(r"^//\s*Maturity:\s*([^—\n]+)", re.M)
errors, seen = [], {}
queries = sorted(QUERY_ROOT.rglob("*.kql"))

for path in queries:
    body = path.read_text(encoding="utf-8")
    rel = path.relative_to(ROOT)
    if not body.strip():
        errors.append(f"{rel}: empty file")
        continue
    for field in REQUIRED:
        if field not in body:
            errors.append(f"{rel}: missing metadata {field}")
    match = ID_RE.search(body)
    if not match:
        errors.append(f"{rel}: missing/malformed unique ID")
    elif match.group(1) in seen:
        errors.append(f"{rel}: duplicate ID {match.group(1)} (also {seen[match.group(1)]})")
    else:
        seen[match.group(1)] = str(rel)
    maturity = MATURITY_RE.search(body)
    if not maturity or maturity.group(1).strip() not in MATURITY:
        errors.append(f"{rel}: missing or unrecognized maturity label")
    if not re.search(r"\b(project|summarize|count|where|join|union|extend|search)\b", body):
        errors.append(f"{rel}: no recognizable KQL operator in query")
    if re.search(r"(?i)\b(TODO|REPLACE_ME|YOUR_TENANT_HERE)\b", body):
        errors.append(f"{rel}: unresolved placeholder")
    if not body.endswith("\n"):
        errors.append(f"{rel}: missing final newline")

if not queries:
    errors.append("No KQL files found under detection-queries/")

print(f"Scanned {len(queries)} KQL files; found {len(seen)} unique IDs.")
if errors:
    print("\nQUALITY CHECK FAILURES:")
    print("\n".join(f" - {item}" for item in errors))
    sys.exit(1)
print("Static metadata and repository checks passed.")
print("NOTE: Not KQL parser validation, tenant schema validation, or behavioural testing.")
