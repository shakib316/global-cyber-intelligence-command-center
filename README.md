# Global Cyber Intelligence Command Center (GCI)

A GitHub-hosted cyber-intelligence dashboard and daily collection pipeline for vulnerabilities, exploited flaws, threat research, campaigns, indicators, and cybersecurity business developments.

**Live dashboard:** https://shakib316.github.io/global-cyber-intelligence-command-center/  
**Source repository:** https://github.com/shakib316/global-cyber-intelligence-command-center

> **Deployment and privacy:** The current dashboard is published using GitHub Pages from a public repository. Do not place secrets, private incident data, customer information, internal asset inventories, or confidential indicators in this repository or browser-local tools. This is not currently a private/self-hosted platform.

## Implemented capabilities

- Scheduled public-feed collection and dated JSON/Markdown snapshots.
- CISA Known Exploited Vulnerabilities (KEV) catalogue and recent additions.
- Government CERT/advisory, vendor PSIRT, cloud-provider, and security-research feeds.
- Cybersecurity business and market news feeds, including M&A, funding, partnerships, products, leadership, and workforce developments.
- Source health and collection-error reporting.
- Source-page enrichment where publicly retrievable, with feed-only/limited enrichment distinguished.
- Threat cards with technical context, CVE references, evidence links, and adjacent remediation status.
- Critical vulnerability watch, searchable/filterable KEV catalogue, historical daily reports, and date navigation.
- IOC candidate extraction for analyst verification; candidates are not blocklists.
- Browser-local watchlist, local asset-to-KEV text matcher, snapshot comparison, and executive digest.
- KQL detection-query library with maturity labels and static metadata checks.
- GitHub Actions for daily collection, dashboard validation, query-library checks, and GitHub Pages deployment.

## Collection and reporting model

The collector uses public RSS/Atom feeds and public advisory/catalogue endpoints. It is not an exhaustive view of the internet and does not use authenticated or paid intelligence feeds unless separately configured.

Each daily report records collection time and coverage window, per-source health, threat/advisory descriptions, technical context where retrieved, CVEs and evidence links where present, remediation status, business context, and collection limitations.

### Remediation semantics

- A concrete version, KB, command, configuration, or other actionable instruction is shown only when extracted from source text.
- Generic phrases such as "follow vendor instructions" are not presented as a fix.
- "No specific fix identified" means the retrieved material did not establish one; it does not prove that no vendor fix exists.
- A CISA KEV due date is a compliance deadline for covered entities, not proof that a patch has been installed.
- Deployment state is unknown without asset or patch-management telemetry.
- Vendor-specific fixed-version verification is not yet automated for every CVE/KEV entry.

## Detection engineering

The detection-queries directory contains KQL examples and templates. Query maturity is explicit: Draft, Schema-checked, Syntax-validated, Lab-tested, Production-approved, or Retired.

Current CI validates metadata, IDs, placeholders, and repository hygiene. It does not parse KQL, validate tenant-specific table/column schemas, execute queries, measure false positives, or prove production effectiveness. Treat Draft queries as starting points requiring tenant adaptation and testing. SPL and Google SecOps YARA-L folders currently contain guidance/placeholders rather than a complete equivalent library.

## Automation

- Daily collector schedule: 09:00 Asia/Kolkata (03:30 UTC).
- Dashboard quality workflow: scheduled checks and checks after relevant pushes/workflow completions.
- GitHub Pages deploys on dashboard and intelligence artifact changes.
- Detection-query CI runs on query-library changes and pull requests.

A successful workflow confirms only the steps in that workflow. Feed-level failures are reported separately and do not mean full global coverage.

## Known limitations

- Public feeds are incomplete and may be delayed, unavailable, rate-limited, or change format.
- CERT-In is currently an index-scraping source and may fail; confirm advisories directly on CERT-In.
- Individual feeds, including Australian ACSC, can fail independently.
- CVSS/EPSS, exploit validation, actor attribution, and IOC reputation are not universally available or independently verified for every item.
- Business-news feeds can contain duplicate, syndicated, market/stock, or low-relevance results; corroborate major deal claims with company announcements, filings, or multiple independent reports.
- No automated containment, blocking, ticket creation, or production remediation is performed.
- No private asset inventory or authenticated SIEM data is connected.

## Repository layout

- index.html — dashboard UI.
- scripts/collect_threat_intel.py — public-source collection, enrichment, normalization, and report generation.
- scripts/validate_dashboard.py — dashboard, latest-data, and remediation regression checks.
- scripts/validate_detection_queries.py — static query metadata checks.
- .github/workflows/ — collection, validation, query CI, and Pages deployment.
- intel/daily/ — daily Markdown intelligence reports.
- intel/snapshots/ — dated JSON source snapshots.
- intel/latest.json — pointer to the latest report and snapshot.
- detection-queries/ — categorized detection query library.

## Security and operational guidance

Never commit API tokens, passwords, private keys, .env files, confidential indicators, or internal incident data. If the project is later moved to a private Azure deployment, add authentication, TLS, access control, secret management, backups, monitoring, and a review of public-data retention before exposing it to users.

## Local validation

Run:
- python scripts/validate_detection_queries.py
- python scripts/validate_dashboard.py

A green static check is not a substitute for browser-based testing, KQL execution, tenant-schema validation, or analyst review.
## Data quality and evidence policy

See [INTELLIGENCE_QUALITY.md](INTELLIGENCE_QUALITY.md) for CVE extraction, vendor remediation evidence, business-event classification, detection-query maturity, and validation limitations.
