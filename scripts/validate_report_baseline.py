#!/usr/bin/env python3
"""Validate daily report structure against the 25 November 2026 baseline."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "reports/2026/11/25.md"
EXPECTED_SECTIONS = [
    "## Executive assessment",
    "## 1) YESTERDAY'S THREATS",
    "## 2) TODAY'S THREATS",
    "## 3) CYBERSECURITY BUSINESS & INDUSTRY NEWS",
    "## 4) ACTION CHECKLIST",
    "## 5) QUIET-DAY / VERIFICATION NOTE",
]
EXPECTED_YESTERDAY_COLUMNS = [
    "Threat/name", "Short description", "CVE(s)", "Affected products/versions",
    "Urgency/verified exploit or KEV status",
    "How to detect (telemetry/fields/behaviour)",
    "How to fix (patch/workaround/containment)",
    "Microsoft Sentinel KQL detection query", "Source links/confidence",
]
EXPECTED_SUBSECTIONS = [
    "### 2.1", "### 2.2", "### 2.3", "### 2.4", "### 2.5",
    "### 2.6 Detection queries — complete KQL blocks for today's briefing",
    "### Immediate — today", "### This week",
]


def fail(path: Path, message: str) -> None:
    print(f"::error file={path.relative_to(ROOT)}::{message}")
    raise SystemExit(1)


def first_table_header(text: str) -> list[str] | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("|") and index + 1 < len(lines):
            separator = lines[index + 1].strip()
            if re.fullmatch(r"\|?[\s:|-]+\|?", separator):
                return [cell.strip() for cell in line.strip().strip("|").split("|")]
    return None


def validate(path: Path, baseline_sections: list[str], baseline_columns: list[str]) -> None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(path, f"Cannot read report: {exc}")

    if not content.strip():
        fail(path, "Report is empty.")

    sections = [line.strip() for line in content.splitlines()
                if re.match(r"^##\s", line)]
    if sections != baseline_sections:
        fail(path, "Level-2 section names/order differ from the 25 November baseline. "
                   f"Expected: {baseline_sections}; found: {sections}")

    columns = first_table_header(content)
    if columns != baseline_columns:
        fail(path, "Yesterday's Threats table columns differ from the 25 November baseline. "
                   f"Expected: {baseline_columns}; found: {columns}")

    for required in EXPECTED_SUBSECTIONS:
        if not any(line.strip().startswith(required) for line in content.splitlines()):
            fail(path, f"Missing required baseline subsection: {required}")

    # The report's fenced code blocks and HTML disclosure blocks must be balanced.
    fence_count = sum(1 for line in content.splitlines() if line.strip().startswith("```"))
    if fence_count % 2:
        fail(path, f"Unbalanced Markdown code fences ({fence_count} fence lines).")
    if content.count("<details>") != content.count("</details>"):
        fail(path, "Unbalanced <details> / </details> blocks.")
    if content.count("<summary>") != content.count("</summary>"):
        fail(path, "Unbalanced <summary> / </summary> blocks.")

    # At least one complete KQL block is required in the detection-query section.
    kql_blocks = re.findall(r"^\`\`\`kql\s*$([\s\S]*?)^\`\`\`\s*$",
                            content, flags=re.MULTILINE)
    if not kql_blocks:
        fail(path, "No fenced KQL detection query found.")
    if any(not block.strip() for block in kql_blocks):
        fail(path, "An empty KQL code block was found.")

    print(f"PASS: {path.relative_to(ROOT)} matches the 25 November 2026 report structure "
          f"({len(kql_blocks)} KQL blocks).")


def main() -> None:
    if not BASELINE.is_file():
        raise SystemExit(f"Baseline report not found: {BASELINE}")
    baseline_text = BASELINE.read_text(encoding="utf-8")
    baseline_sections = [line.strip() for line in baseline_text.splitlines()
                         if re.match(r"^##\s", line)]
    baseline_columns = first_table_header(baseline_text)
    if not baseline_columns:
        raise SystemExit("Could not read the baseline Yesterday's Threats table header.")

    paths = [Path(arg).resolve() for arg in sys.argv[1:]]
    paths = [path for path in paths if path != BASELINE.resolve()]
    if not paths:
        print("No changed daily report files to validate.")
        return
    for path in paths:
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise SystemExit(f"Invalid or missing report path: {path}")
        validate(path, baseline_sections, baseline_columns)


if __name__ == "__main__":
    main()
