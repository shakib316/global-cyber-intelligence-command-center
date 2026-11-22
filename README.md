# Global Cyber Intelligence Command Center (GCI)

A private, self-hosted intelligence platform for cyber threats, vulnerabilities, vendor and industry developments, M&A, AI security, geopolitics, and career signals.

## Project goals

- Collect high-value intelligence from authoritative sources and reputable reporting.
- Deduplicate coverage into canonical events with source evidence and timestamps.
- Distinguish verified facts, corroborated reporting, and unconfirmed claims.
- Produce actionable security briefings and detection-engineering leads.
- Deliver a daily digest and high-priority alerts through dashboard, email, and WhatsApp.
- Keep the platform private and under the owner's control.

## Planned architecture

```
Official APIs / RSS / curated sources
              |
       Python collectors
              |
       Normalize + dedupe
              |
   PostgreSQL event/evidence store
              |
 AI-assisted extraction, scoring,
 summarization and correlation
              |
 Dashboard | Email | WhatsApp
          n8n orchestration
```

Core stack: Python, FastAPI, PostgreSQL, n8n, Docker Compose, and a lightweight web dashboard. AI inference will use an external API rather than a local model on the small deployment VM.

## Current status

- [x] Scope and architecture agreed.
- [x] Initial MVP starter bundle designed (Docker Compose, FastAPI, PostgreSQL, n8n, RSS collector, dashboard, configuration and deployment guide).
- [ ] Commit and validate the starter implementation in this repository.
- [ ] Add official CISA KEV and NVD collectors, then CERT-In and vendor advisories.
- [ ] Add event clustering, evidence records, source reliability and confidence labels.
- [ ] Add grounded AI summaries and threat/business relevance scoring.
- [ ] Add detection engineering outputs (Google SecOps YARA-L, Splunk SPL, Microsoft Sentinel KQL).
- [ ] Add daily email, WhatsApp templates and high-priority alert routing.
- [ ] Harden authentication, secrets, backups, monitoring and deployment.

The initial starter bundle is a foundation, not a production-ready threat-intelligence service. All CVE severity, affected versions, exploitation, IOCs and attribution must be verified against primary sources. AI-generated detections must be labelled as drafts until validated.

## Intelligence standards

- Preserve source URL, publisher, published/updated time, first-seen time, and retrieval time.
- Keep claims tied to evidence; do not fabricate IOCs, dates, CVSS scores, attribution or detection test results.
- Use confidence labels: **Verified** (primary source), **Corroborated** (multiple independent credible sources), **Reported** (credible reporting, not independently confirmed), **Unverified** (unconfirmed claims).
- Track M&A as a lifecycle: reported talks → confirmed discussions → definitive agreement → regulatory review → closed/terminated.
- Separate cyber urgency from business significance; apply India/APAC relevance as a ranking factor.

## Deployment target

Ubuntu 22.04 on an Azure VM (2 vCPU, 4 GB RAM) with Docker. Keep services private by default. Do not expose PostgreSQL or n8n publicly; add authentication and TLS before remote dashboard access.

## Security

Never commit `.env`, API tokens, passwords, private keys, or personal notification credentials. Use `.env.example` for placeholders only. Pin container versions and review dependency updates before production deployment.

## Detection query library

A categorized, versioned query collection is maintained in [`detection-queries/`](detection-queries/README.md). KQL is the primary format, organized by Windows, Linux, firewall/network, identity, cloud/containers, virtualization, asset inventory and business applications. SPL and Google SecOps YARA-L equivalents have dedicated locations. Queries carry maturity labels and must be validated against the target tenant's schemas before production use.
