#!/usr/bin/env python3
"""Metadata and lightweight structural checks for SPL/YARA-L; not vendor parsers."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
QUERY_ROOT = ROOT / "detection-queries"
REQUIRED = ("ID:", "Title:", "Platform:", "Type:", "Data source:",
            "Required fields:", "Maturity:", "False positives:", "Tuning:")
MATURITY = {"Draft", "Schema-checked", "Syntax-validated",
            "Lab-tested", "Production-approved", "Retired"}
errors = []
seen = {}

for extension, comment_prefix in ((".spl", "#"), (".yaral", "//")):
    paths = sorted(QUERY_ROOT.rglob("*" + extension))
    for path in paths:
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT)
        if not text.strip():
            errors.append(f"{rel}: empty file")
            continue
        for field in REQUIRED:
            if not re.search(r"^" + re.escape(comment_prefix) + r"\\s*" + re.escape(field), text, re.M):
                errors.append(f"{rel}: missing metadata {field}")
        id_match = re.search(r"^" + re.escape(comment_prefix) + r"\\s*ID:\\s*([A-Z0-9][A-Z0-9-]+)\\s*$", text, re.M)
        if not id_match:
            errors.append(f"{rel}: missing or malformed unique ID")
        elif id_match.group(1) in seen:
            errors.append(f"{rel}: duplicate ID {id_match.group(1)} also used by {seen[id_match.group(1)]}")
        else:
            seen[id_match.group(1)] = str(rel)
        maturity = re.search(r"^" + re.escape(comment_prefix) + r"\\s*Maturity:\\s*([^\\n]+)", text, re.M)
        if not maturity or maturity.group(1).strip() not in MATURITY:
            errors.append(f"{rel}: missing or unrecognized maturity label")
        if re.search(r"(?i)\\b(TODO|REPLACE_ME|YOUR_TENANT_HERE)\\b", text):
            errors.append(f"{rel}: unresolved placeholder")
        if not text.endswith("\\n"):
            errors.append(f"{rel}: missing final newline")
        if extension == ".spl":
            body = "\\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")).strip()
            if not body or "|" not in body:
                errors.append(f"{rel}: no recognizable SPL pipeline")
            if body.count('"') % 2:
                errors.append(f"{rel}: unbalanced double-quoted string")
        else:
            if not re.search(r"^\\s*rule\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\{", text, re.M):
                errors.append(f"{rel}: missing YARA-L rule declaration")
            for section in ("meta:", "events:", "condition:"):
                if section not in text:
                    errors.append(f"{rel}: missing YARA-L {section} section")
            if text.count("{") != text.count("}"):
                errors.append(f"{rel}: unbalanced rule braces")
            if text.count("`") % 2:
                errors.append(f"{rel}: unbalanced YARA-L raw-string delimiter")

print(f"Scanned {len(list(QUERY_ROOT.rglob('*.spl')))} SPL and {len(list(QUERY_ROOT.rglob('*.yaral')))} YARA-L files; found {len(seen)} unique IDs.")
if errors:
    print("\\nQUALITY CHECK FAILURES:\\n" + "\\n".join(" - " + item for item in errors))
    sys.exit(1)
print("SPL/YARA-L metadata and lightweight structure checks passed.")
print("LIMITATION: These checks are not the official Splunk SPL parser or Google SecOps YARA-L compiler, nor tenant-schema or behavioural validation.")
