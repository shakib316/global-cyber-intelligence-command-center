# Global Cyber Intelligence Command Center (GCI)

A GitHub-hosted cyber-intelligence dashboard and daily collection pipeline for vulnerabilities, exploited flaws, threat research, and cybersecurity business developments.

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

## Threat actor and campaign intelligence
