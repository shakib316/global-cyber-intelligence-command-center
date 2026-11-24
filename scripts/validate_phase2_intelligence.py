#!/usr/bin/env python3
"""Evidence and referential-integrity checks for actor/campaign intelligence."""
import json, re, sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "intel/phase2-intelligence.json"
SCHEMA_PATH = ROOT / "intel/schemas/phase2-intelligence.schema.json"

def fail(message):
    raise SystemExit("Phase 2 intelligence validation failed: " + message)

def unique(records, label):
    ids = [x.get("id") for x in records]
    if any(not x for x in ids):
        fail(label + " contains a record without an ID")
    if len(ids) != len(set(ids)):
        fail(label + " contains duplicate IDs")

def parse_date(value, label):
    if value is None:
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        fail(label + " has an invalid ISO timestamp: " + str(value))

if not DATA_PATH.exists() or not SCHEMA_PATH.exists():
    fail("dataset or JSON schema is missing")
data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
    fail("schema must declare JSON Schema 2020-12")
if data.get("schema_version") != "1.0":
    fail("unsupported dataset schema version")
parse_date(data.get("generated_at"), "dataset generated_at")
sources = data.get("sources", [])
actors = data.get("actors", [])
campaigns = data.get("campaigns", [])
relationships = data.get("relationships", [])
unique(sources, "sources")
unique(actors, "actors")
unique(campaigns, "campaigns")
unique(relationships, "relationships")
source_ids = {x["id"] for x in sources}
actor_ids = {x["id"] for x in actors}
campaign_ids = {x["id"] for x in campaigns}
for source in sources:
    if not str(source.get("url", "")).startswith("https://"):
        fail("source URL must use HTTPS: " + str(source.get("id")))
    parse_date(source.get("retrieved_at"), "source retrieved_at")
for actor in actors:
    if actor.get("confidence") not in {"High", "Medium", "Low", "Unknown"}:
        fail("actor confidence is invalid: " + actor["id"])
    if not actor.get("confidence_rationale") or not actor.get("source_ids"):
        fail("actor lacks confidence rationale or evidence: " + actor["id"])
    if set(actor.get("source_ids", [])) - source_ids:
        fail("actor references an unknown evidence source: " + actor["id"])
    if set(actor.get("campaign_ids", [])) - campaign_ids:
        fail("actor references an unknown campaign: " + actor["id"])
    if set(actor.get("techniques", [])) - {t for c in campaigns for t in c.get("techniques", [])} and not actor.get("source_ids"):
        fail("actor technique mapping lacks evidence: " + actor["id"])
    parse_date(actor.get("record_updated_at"), "actor record_updated_at")
for campaign in campaigns:
    if campaign.get("confidence") not in {"High", "Medium", "Low", "Unknown"}:
        fail("campaign confidence is invalid: " + campaign["id"])
    if not campaign.get("confidence_rationale") or not campaign.get("source_ids"):
        fail("campaign lacks confidence rationale or evidence: " + campaign["id"])
    if set(campaign.get("source_ids", [])) - source_ids:
        fail("campaign references an unknown evidence source: " + campaign["id"])
    if set(campaign.get("actor_ids", [])) - actor_ids:
        fail("campaign references an unknown actor: " + campaign["id"])
    if any(not re.fullmatch(r"T[0-9]{4}(?:\\.[0-9]{3})?", t) for t in campaign.get("techniques", [])):
        fail("campaign has malformed ATT&CK technique ID: " + campaign["id"])
    if any(not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", c) for c in campaign.get("cve_ids", [])):
        fail("campaign has malformed CVE ID: " + campaign["id"])
    parse_date(campaign.get("record_updated_at"), "campaign record_updated_at")
entity_ids = {"actor": actor_ids, "campaign": campaign_ids,
              "technique": {t for a in actors for t in a.get("techniques", [])} | {t for c in campaigns for t in c.get("techniques", [])},
              "cve": {c for a in actors for c in a.get("cve_ids", [])} | {c for c in campaigns for c in c.get("cve_ids", [])},
              "ioc": {i for a in actors for i in a.get("ioc_ids", [])} | {i for c in campaigns for i in c.get("ioc_ids", [])}}
for rel in relationships:
    if rel.get("from_id") not in entity_ids.get(rel.get("from_type"), set()):
        fail("relationship has unresolved from entity: " + rel["id"])
    if rel.get("to_id") not in entity_ids.get(rel.get("to_type"), set()):
        fail("relationship has unresolved to entity: " + rel["id"])
    if rel.get("confidence") not in {"High", "Medium", "Low", "Unknown"}:
        fail("relationship confidence is invalid: " + rel["id"])
    if set(rel.get("source_ids", [])) - source_ids:
        fail("relationship references an unknown evidence source: " + rel["id"])
    if not rel.get("rationale"):
        fail("relationship has no rationale: " + rel["id"])
print("Phase 2 intelligence checks passed:", len(actors), "actors,", len(campaigns), "campaigns,", len(relationships), "evidence-linked relationships,", len(sources), "sources.")
print("This validates data structure and provenance links; it does not independently verify source claims.")
