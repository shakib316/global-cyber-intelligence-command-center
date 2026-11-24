# Global Cyber Intelligence Command Center — Architecture

## System overview

The project is a public, GitHub Pages-hosted analyst-support dashboard backed by a scheduled GitHub Actions collection pipeline. It is not a private SOC platform and does not connect to an organisation's authenticated SIEM, EDR, asset inventory, ticketing or response systems.

Public advisory, research and vendor feeds
→ GitHub Actions collector
→ normalization, enrichment, deduplication and source-health tracking
→ dated JSON snapshots, daily Markdown reports and Phase 2 intelligence records
→ validation gates
→ GitHub Pages deployment
→ browser dashboard

## Data contracts

| Artifact | Purpose |
|---|---|
| intel/latest.json | Pointer to the current dated snapshot and report |
| intel/snapshots/YYYY/MM/DD.json | Daily structured intelligence, source health, KEV and candidate IOC data |
| intel/source-health-state.json | Per-source last attempt, last success and consecutive failure state |
| intel/phase2-intelligence.json | Evidence-linked actor, campaign and relationship dataset |
| intel/schemas/phase2-intelligence.schema.json | JSON Schema 2020-12 contract for Phase 2 records |
| detection-queries/ | KQL, SPL and Google SecOps YARA-L query library |
| reports/YYYY/MM/DD.md | Analyst-facing dated briefing |

The browser loads the latest snapshot through intel/latest.json. Historical reports are discovered from the repository archive. Actor/campaign data is loaded separately from intel/phase2-intelligence.json. Detection query files are fetched from the repository when the analyst opens the query library.

## Trust and evidence model

- Public feeds are incomplete and may be delayed, rate-limited, unavailable or changed without notice.
- Material actor/campaign claims and relationships retain source IDs and rationale. Source-reported attribution is not independently confirmed by this dashboard.
- An empty CVE/IOC association is a valid outcome; missing evidence must not be filled with assumptions.
- IOC extraction produces candidates, not confirmed malicious indicators or blocklists.
- CVSS, EPSS and CISA KEV are separate signals. A high CVSS score is not proof of exploitation; KEV membership is not proof an organisation is exposed or patched.
- Extracted remediation candidates remain unverified until analyst review confirms exact product, branch and fixed-release applicability.
- Detection maturity is explicit. Static checks do not prove vendor parser acceptance, tenant schema compatibility, behavioural correctness or production effectiveness.

## Security boundaries

- The collector validates public HTTPS destinations, resolves and pins public IPs, revalidates redirects and applies bounded retry/timeout behaviour.
- The dashboard escapes dynamic text before HTML insertion and routes external links through an HTTPS-only URL helper.
- A GitHub Pages-compatible Content Security Policy is set in a meta tag. The current single-file UI retains inline JavaScript and CSS, so unsafe-inline is an explicit compatibility trade-off; this is not a nonce/hash-based strict CSP.
- The repository and published site are public. Never commit credentials, customer data, private incident details, internal asset inventories or confidential indicators.
- Browser-local watchlists and asset matching are local analyst conveniences, not server-side protected storage or verified asset integrations.

## Deployment flow

The daily collection workflow is the canonical automatic deployment path. It validates and commits the collection, then checks out the latest main branch before building the Pages artifact. The standalone Pages workflow is retained for manual dispatch only to avoid concurrent automatic deployments racing each other.

A successful GitHub Pages deployment confirms that GitHub accepted the deployment artifact. It does not, by itself, prove that every external source is current or that a human browser session has rendered every control correctly.

## Validation boundaries

Automated checks cover repository structure, latest snapshot integrity, unique IDs, source and relationship references, collector safeguards, dashboard JavaScript syntax, selected functional invariants, query metadata and lightweight structure, and frontend escaping/URL/Markdown regression cases.

The current checks do not replace:
- browser-driven end-to-end tests across desktop/tablet/mobile;
- screen-reader, keyboard-only and manual contrast review;
- official KQL/SPL/YARA-L parser validation;
- positive/negative execution against representative query fixtures in each SIEM;
- tenant schema and telemetry readiness checks;
- analyst review of every attribution, IOC reputation and remediation claim;
- integration with real asset, patch, exposure or business-criticality inventories.
