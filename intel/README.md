# Automated Threat Intelligence Snapshots

The daily GitHub Actions workflow collects two public feeds:

- **CISA Known Exploited Vulnerabilities (KEV):** vulnerability exploitation prioritization. KEV records are not network IOCs.
- **URLhaus recent feed:** malicious URL observations, normalized into URL/domain or IP indicators.

Each UTC-dated run stores:
- `daily/YYYY/MM/DD.md` — readable snapshot, source health, recent KEV additions, sample indicators and limitations.
- `indicators/YYYY/MM/DD.json` — raw normalized evidence, source URLs, retrieval time and confidence context.
- `detection-queries/generated/YYYY/MM/urlhaus_ioc_hunt_YYYY-MM-DD.kql` — generated Defender XDR/Sentinel hunt, always labelled Draft.

## Important limitations

This is an initial feed-driven pipeline, not comprehensive threat intelligence. It does not automatically discover all ransomware victims, APT campaigns, active intrusions, CERT-In advisories or vendor vulnerabilities. Add source-specific collectors only with documented licensing, rate limits, parsing and provenance.

A feed match is an investigation lead, not proof of compromise. Review IOC freshness, tenant telemetry, false positives and query schema before use. The workflow does not block, quarantine, disable accounts or promote queries to production.
