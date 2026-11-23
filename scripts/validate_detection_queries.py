#!/usr/bin/env python3
"""Structural KQL lint and metadata checks; not a Microsoft Kusto parser or tenant execution."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
QUERY_ROOT = ROOT / "detection-queries"
REQUIRED = ("ID:", "Title:", "Platform:", "Type:", "Data source:", "Required fields:",
            "Maturity:", "False positives:", "Tuning:")
MATURITY = {"Draft", "Schema-checked", "Syntax-validated",
            "Lab-tested", "Production-approved", "Retired"}
ID_RE = re.compile(r"^//\s*ID:\s*([A-Z0-9][A-Z0-9-]+)\s*$", re.M)
MATURITY_RE = re.compile(r"^//\s*Maturity:\s*([^—\n]+)", re.M)
def structural_kql_errors(query):
    """Catch common lexical/pipeline mistakes without claiming full KQL parsing."""
    errors = []
    stack = []
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = None
    i = 0
    line = 1
    while i < len(query):
        ch = query[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if quote:
            if ch == quote:
                if i + 1 < len(query) and query[i + 1] == quote:
                    i += 2
                    continue
                quote = None
            elif ch == "\\" and i + 1 < len(query):
                i += 2
                continue
            i += 1
            continue
        if ch == "/" and i + 1 < len(query) and query[i + 1] == "/":
            end = query.find("\n", i)
            if end < 0:
                break
            i = end
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "([{":
            stack.append((ch, line))
        elif ch in ")]}":
            if not stack or stack[-1][0] != pairs[ch]:
                errors.append(f"line {line}: unmatched closing {ch}")
            else:
                stack.pop()
        i += 1
    if quote:
        errors.append("unterminated string literal")
    for opening, opened_line in stack:
        errors.append(f"line {opened_line}: unclosed {opening}")
    body_lines = [line.strip() for line in query.splitlines() if line.strip() and not line.strip().startswith("//")]
    if not body_lines:
        errors.append("query body is empty")
    if body_lines and re.fullmatch(r"\|\s*", body_lines[-1]):
        errors.append("query ends with a dangling pipe")
    for number, line_text in enumerate(query.splitlines(), 1):
        stripped = line_text.strip()
        if stripped.startswith("|") and not re.match(r"^\|\s*[A-Za-z_][A-Za-z0-9_]*\b", stripped):
            errors.append(f"line {number}: pipe is not followed by a KQL operator")
    return errors


errors, seen = [], {}
queries = sorted(p for p in QUERY_ROOT.rglob("*.kql") if p.name != "QUERY_TEMPLATE.kql")

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
    query_body = body.split("\n\n", 1)[-1]
    errors.extend(f"{rel}: {message}" for message in structural_kql_errors(query_body))

if not queries:
    errors.append("No KQL files found under detection-queries/")

# Regression checks for the structural lexer itself.
if structural_kql_errors('DeviceProcessEvents\n| where ProcessCommandLine has "encoded"'):
    errors.append("structural lexer rejected a simple valid KQL pipeline")
if not structural_kql_errors('DeviceProcessEvents\n| where ProcessCommandLine has "unterminated'):
    errors.append("structural lexer failed to detect an unterminated string")
if not structural_kql_errors('DeviceProcessEvents\n| where (Timestamp > ago(1h)'):
    errors.append("structural lexer failed to detect an unclosed delimiter")

print(f"Scanned {len(queries)} KQL files; found {len(seen)} unique IDs.")
if errors:
    print("\nQUALITY CHECK FAILURES:")
    print("\n".join(f" - {item}" for item in errors))
    sys.exit(1)
print("Metadata and structural KQL checks passed (balanced delimiters, quoted strings, pipeline operators, required fields).")
print("LIMITATION: Not the official Microsoft Kusto parser, tenant schema validation, or behavioural/lab testing. Queries retain their declared maturity.")
