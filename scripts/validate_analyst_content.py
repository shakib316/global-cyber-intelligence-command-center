#!/usr/bin/env python3
"""Validate the public analyst-enrichment contract for the latest intelligence snapshot."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LATEST_PATH = ROOT / "intel" / "latest.json"
ALLOWED_REMEDIATION = {
    "FIX VERIFIED",
    "MITIGATION VERIFIED",
    "SPECIFIC ACTION — VERIFY",
    "CANDIDATE RELEASE — VERIFY",
    "VENDOR REPORTS NO FIX",
    "WORKAROUND — PORTAL ACCESS",
    "NOT ESTABLISHED",
}


def fail(message: str) -> None:
    raise SystemExit(f"Analyst content validation failed: {message}")


def validate_record(record: dict, label: str) -> None:
    if not record.get("analyst_reviewed"):
        fail(f"{label} is not marked analyst_reviewed")
    background = record.get("technology_background")
    if not isinstance(background, dict):
        fail(f"{label} has no structured technology_background")
    if not str(background.get("what_is_it", "")).strip():
        fail(f"{label} is missing Technology background / What is it?")
    if not str(background.get("what_does_it_do", "")).strip():
        fail(f"{label} is missing Technology background / What does it do?")
    details = record.get("technical_details")
    if not isinstance(details, list) or len(details) > 4:
        fail(f"{label} must have at most four technical-detail lines")
    if any(not str(line).strip() for line in details):
        fail(f"{label} contains an empty technical-detail line")
    status = record.get("remediation_status")
    if status not in ALLOWED_REMEDIATION:
        fail(f"{label} has unsupported remediation status: {status!r}")
    refs = record.get("vendor_references")
    if not isinstance(refs, list) or len(refs) > 3:
        fail(f"{label} must have no more than three source links")
    for ref in refs:
        url = str(ref.get("url", ""))
        if not url.startswith(("https://", "http://")):
            fail(f"{label} contains a non-HTTP source URL")


def main() -> None:
    if not LATEST_PATH.exists():
        print("No intel/latest.json; analyst-content validation skipped.")
        return
    latest = json.loads(LATEST_PATH.read_text(encoding="utf-8"))
    relative = latest.get("snapshot")
    if not relative:
        fail("latest.json has no snapshot path")
    snapshot_path = ROOT / "intel" / relative
    if not snapshot_path.exists():
        fail(f"latest snapshot is missing: {snapshot_path}")
    data = json.loads(snapshot_path.read_text(encoding="utf-8"))

    # Historical/raw snapshots without analyst-review metadata are not rewritten by this validator.
    if not data.get("analyst_enrichment"):
        print("Latest snapshot has no analyst-enrichment publication; validation skipped.")
        return

    if latest.get("date_ist") != data.get("date_ist"):
        fail("latest.json date does not match snapshot date")
    if data.get("window_hours") != 24 or data.get("business_window_hours") != 24:
        fail("published snapshot must use the requested rolling 24-hour window")
    if data.get("successful_sources") != data.get("total_sources"):
        fail("not all configured source feeds reported success")

    items = data.get("items", [])
    business = data.get("business_items", [])
    quarantined = data.get("quarantined_items", [])
    quarantined_business = data.get("quarantined_business_items", [])

    for index, item in enumerate(items):
        validate_record(item, f"threat item {index + 1}: {item.get('title', 'untitled')}")
    for index, item in enumerate(business):
        validate_record(item, f"business item {index + 1}: {item.get('title', 'untitled')}")
        background = item["technology_background"]
        if "not applicable" not in background["what_is_it"].lower():
            fail(f"business item {item.get('title')} must label technology background Not applicable")

    for index, item in enumerate(quarantined):
        if not item.get("reason") or not isinstance(item.get("raw_record"), dict):
            fail(f"quarantined threat record {index + 1} must retain raw_record and reason")
    for index, item in enumerate(quarantined_business):
        if not item.get("reason") or not isinstance(item.get("raw_record"), dict):
            fail(f"quarantined business record {index + 1} must retain raw_record and reason")

    if data.get("raw_item_count") != len(items) + len(quarantined):
        fail("raw threat count does not reconcile with published + quarantined records")
    if data.get("raw_business_item_count") != len(business) + len(quarantined_business):
        fail("raw business count does not reconcile with published + quarantined records")
    if data.get("business_feed_count") != data.get("raw_business_item_count"):
        fail("business_feed_count must preserve the raw feed count")
    print(
        "Analyst content validated: "
        f"{len(items)} threat items, {len(business)} business items, "
        f"{len(quarantined)} threat quarantines, {len(quarantined_business)} business quarantines; "
        f"{data.get('successful_sources')}/{data.get('total_sources')} sources; 24-hour window."
    )


if __name__ == "__main__":
    main()
