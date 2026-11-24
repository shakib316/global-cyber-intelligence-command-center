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

from copy import deepcopy
from urllib.parse import urlsplit

def resolve_ref(root_schema, ref):
    if not ref.startswith("#/"):
        raise ValueError("Only local JSON Schema references are supported: " + ref)
    value = root_schema
    for part in ref[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        value = value[key]
    return value

def schema_errors(value, rule, root_schema=None, path="$"):
    """Validate the JSON Schema subset used by the checked-in 2020-12 contract."""
    root_schema = root_schema or rule
    errors = []
    if "$ref" in rule:
        try:
            target = resolve_ref(root_schema, rule["$ref"])
        except (KeyError, ValueError) as exc:
            return [path + ": unresolved schema reference: " + str(exc)]
        return schema_errors(value, target, root_schema, path)
    expected = rule.get("type")
    if expected:
        choices = expected if isinstance(expected, list) else [expected]
        checks = {
            "object": lambda x: isinstance(x, dict),
            "array": lambda x: isinstance(x, list),
            "string": lambda x: isinstance(x, str),
            "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
            "number": lambda x: isinstance(x, (int, float)) and not isinstance(x, bool),
            "boolean": lambda x: isinstance(x, bool),
            "null": lambda x: x is None,
        }
        if not any(checks[k](value) for k in choices):
            return [path + ": expected " + " or ".join(choices)]
    if "const" in rule and value != rule["const"]:
        errors.append(path + ": value does not match required constant")
    if "enum" in rule and value not in rule["enum"]:
        errors.append(path + ": value is outside the allowed enumeration")
    if isinstance(value, str):
        if len(value) < rule.get("minLength", 0):
            errors.append(path + ": string is shorter than minLength")
        if "pattern" in rule and not re.search(rule["pattern"], value):
            errors.append(path + ": string does not match required pattern")
        fmt = rule.get("format")
        if fmt == "date":
            try:
                dt.date.fromisoformat(value)
            except ValueError:
                errors.append(path + ": invalid ISO date")
        elif fmt == "date-time":
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    errors.append(path + ": date-time must include a timezone")
            except ValueError:
                errors.append(path + ": invalid ISO date-time")
        elif fmt == "uri":
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.netloc:
                errors.append(path + ": invalid absolute URI")
    if isinstance(value, list):
        if len(value) < rule.get("minItems", 0):
            errors.append(path + ": array has fewer than minItems")
        if rule.get("uniqueItems"):
            encoded = [json.dumps(x, sort_keys=True, ensure_ascii=False) for x in value]
            if len(encoded) != len(set(encoded)):
                errors.append(path + ": array items are not unique")
        if isinstance(rule.get("items"), dict):
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, rule["items"], root_schema, path + "[" + str(index) + "]"))
    if isinstance(value, dict):
        properties = rule.get("properties", {})
        for key in rule.get("required", []):
            if key not in value:
                errors.append(path + ": missing required property " + key)
        for key, item in value.items():
            if key in properties:
                errors.extend(schema_errors(item, properties[key], root_schema, path + "." + key))
            elif rule.get("additionalProperties") is False:
                errors.append(path + ": unexpected property " + key)
            elif isinstance(rule.get("additionalProperties"), dict):
                errors.extend(schema_errors(item, rule["additionalProperties"], root_schema, path + "." + key))
    return errors

schema_failures = schema_errors(data, schema)
if schema_failures:
    fail("JSON Schema validation errors: " + "; ".join(schema_failures[:20]))

# Negative fixtures prove that the schema gate rejects representative bad records.
negative_fixtures = []
missing_required = deepcopy(data)
missing_required.pop("sources", None)
negative_fixtures.append(("missing required root field", missing_required))
if data.get("sources"):
    unsafe_source = deepcopy(data)
    unsafe_source["sources"][0]["url"] = "javascript:alert(1)"
    negative_fixtures.append(("unsafe source URL", unsafe_source))
if data.get("actors"):
    invalid_actor = deepcopy(data)
    invalid_actor["actors"][0]["confidence"] = "Certain"
    negative_fixtures.append(("invalid actor confidence", invalid_actor))
if data.get("relationships"):
    extra_relationship = deepcopy(data)
    extra_relationship["relationships"][0]["unexpected_field"] = "not allowed"
    negative_fixtures.append(("unexpected relationship property", extra_relationship))
for label, fixture in negative_fixtures:
    if not schema_errors(fixture, schema):
        fail("JSON Schema regression fixture was incorrectly accepted: " + label)
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
    parse_date(source.get("retrieved_on"), "source retrieved_on")
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
    if any(not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", t) for t in campaign.get("techniques", [])):
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
print("JSON Schema 2020-12 checks passed, including negative fixtures.")
print("Phase 2 intelligence checks passed:", len(actors), "actors,", len(campaigns), "campaigns,", len(relationships), "evidence-linked relationships,", len(sources), "sources.")
print("This validates data structure and provenance links; it does not independently verify source claims.")
