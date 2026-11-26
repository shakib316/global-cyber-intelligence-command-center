# MASTER_REQUIREMENTS.md
# Global Cyber Intelligence Command Center — Master Requirements & Operating Rules

**Status:** Controlling project reference  
**Repository:** `shakib316/global-cyber-intelligence-command-center`  
**Default branch:** `main`  
**Live website:** https://shakib316.github.io/global-cyber-intelligence-command-center/  
**Last reviewed:** 25 November 2026

This document is the single high-level reference for the product's purpose, scope, user requirements, operating schedule, quality standards, AI-assistant instructions and repository-maintenance rules. Read it before making material changes.

## 1. Product mission

Build and maintain a reliable, clear, technically useful **Global Cyber Intelligence Command Center** for security practitioners. It should turn trustworthy public cyber sources into actionable, evidence-linked intelligence about vulnerabilities, active exploitation, threats, detection opportunities and cybersecurity industry developments.

The dashboard is an analyst-support and situational-awareness product. It is **not** a commercial threat-intelligence feed, a private SOC, an authenticated SIEM, a patch-management system or an automated response platform.

### Primary reader and writing level
Write for a Security Engineer with 7 years of experience across SIEM/SOAR, Google SecOps, Splunk, Microsoft Sentinel, detection engineering, cloud security and incident response. Use technically meaningful details without unnecessary explanation or padding.

### Product principles
1. Accuracy and provenance before volume.
2. Actionable detail before decorative UI.
3. Freshness with transparent collection windows and source-health reporting.
4. Clear distinction between fact, vendor statement, researcher observation, media report and analyst assessment.
5. No invented CVEs, versions, fixes, IOCs, attribution, exploitation, dates, query validation or source coverage.
6. Simple, consistent, responsive and accessible interface.
7. Automation must be observable, testable, recoverable and least-privileged.
8. No autonomous containment, blocking or production remediation.

## 2. Current product scope

### Current navigation — preserve this order
1. Overview
2. Daily Briefing
3. New Intelligence
4. Cyber Business
5. CISA KEV
6. Detection Queries
7. Source Health

### Current capabilities to preserve
- Daily public-source threat/advisory collection and structured snapshots.
- CISA Known Exploited Vulnerabilities (KEV) catalogue and recent additions.
- Government, CERT, vendor PSIRT, cloud-provider and security-research sources.
- Cybersecurity business and market developments.
- Source health, last-attempt/last-success information and explicit failure states.
- CVE extraction, source-linked context and remediation evidence states.
- Potential IOC extraction for analyst review; candidates are not confirmed malicious indicators or blocklists.
- KQL, SPL and Google SecOps YARA-L query library with honest maturity labels.
- Date-aware daily briefing and historical report navigation where supported by the current data.
- Overview-only **Critical Vulnerabilities Watch**.
- GitHub Actions validation and GitHub Pages deployment.

### Explicitly retired — do not reintroduce without user approval
The following standalone features were removed to simplify the product:
- Standalone Threat Actors and Campaigns pages/datasets/navigation.
- Overview Threat Operations Toolkit, including personal watchlist, asset exposure matcher, IOC correlation UI, ATT&CK/readiness panel, snapshot comparison, threat relationship mapping and executive digest controls.
- Related watchlist controls on threat, KEV and business cards.

Do not restore these features merely because they appear in old commits, historic audit notes, old documentation or stale validators. Individual threat write-ups may mention a threat actor or campaign when relevant and source-supported; this does not authorize a standalone tracking feature. Backend IOC candidate extraction remains in scope because it supports analyst review and generated candidate hunts.

### Critical vulnerabilities placement
The **Critical Vulnerabilities Watch appears only on Overview**. Do not duplicate that watch panel across Daily Briefing, New Intelligence, Cyber Business, CISA KEV, Detection Queries or Source Health. The full searchable KEV catalogue belongs on the CISA KEV page.

## 3. Daily automation schedule — verified configuration

Times below are Asia/Kolkata (IST).

| Workflow | Current trigger | Responsibility |
|---|---|---|
| Daily Threat Intelligence Collection | Daily at **09:00 IST** (`03:30 UTC`) | Collect public intelligence, validate the snapshot, commit changed `intel/` and generated detection artifacts, then deploy Pages. |
| Dashboard Quality Watch | Every **10 minutes**, plus relevant pushes and completion of configured workflows | Validate dashboard/data integrity and frontend security. This is a quality check, not a fresh intelligence collection. |
| Detection Query Quality Checks | Relevant pushes, pull requests and manual dispatch | Validate query metadata/structure, dashboard, collector and frontend safeguards. |

### Daily collection sequence
1. Workflow starts on schedule or manual dispatch on `main`.
2. Collector retrieves configured public advisories, research feeds, KEV and business-news sources.
3. Collector normalizes, deduplicates, enriches and records source health.
4. Snapshot/dashboard validation and static detection-query checks run.
5. Changed `intel/` and `detection-queries/generated/` artifacts are committed to `main`.
6. Deploy job checks out the latest `main`, verifies its SHA against remote `main`, creates the Pages artifact and deploys the dashboard.
7. Quality Watch runs independently on its configured schedule and workflow events.

**Important implementation distinction:** The current daily workflow's Git commit step stages `intel/` and `detection-queries/generated/`; it does not currently stage `reports/`. Do not claim that the analyst-facing `reports/YYYY/MM/DD.md` archive is automatically published by this workflow until the workflow is deliberately updated and verified. Collector-generated `intel/daily/` artifacts and analyst-facing `reports/` are distinct paths.

### Schedule maintenance rules
- Preserve the daily 09:00 IST collection unless the user explicitly changes it.
- Do not confuse the 10-minute Quality Watch with collection frequency.
- Do not create overlapping Pages deployments or competing scheduled collectors.
- After changing schedules, inspect the workflow YAML and verify the next successful run.
- A green workflow means its configured steps passed; it does not prove every feed or intelligence claim is complete.

## 4. Required website content

### 4.1 Overview
- High-signal summary of current intelligence.
- Critical Vulnerabilities Watch, only here.
- Show material status, dates and links; avoid repeating entire threat write-ups.
- Do not imply the dashboard knows the user's asset exposure or patch state.

### 4.2 Daily Briefing
The briefing should be concise, analyst-friendly and useful without requiring repeated source visits. Use the controlling detailed format in [REPORTING_STANDARD.md](REPORTING_STANDARD.md).

Minimum content:
- Report date, generation timestamp in IST and exact coverage window.
- Yesterday's threats in a structured table.
- Today's threats as individual concise write-ups.
- Detection guidance and remediation adjacent to each relevant threat.
- Full detection queries in clearly titled query blocks, with matching short Q# references in the table/write-ups.
- Mandatory Cybersecurity Business & Industry News section.
- Immediate and this-week action checklist.
- Quiet-day, verification and source-failure note.

### 4.3 New Intelligence
- Newly collected and materially relevant advisories, vulnerabilities and research.
- Each item should show source, publication date, CVE where applicable, affected product/version where known, exploitation/KEV context, evidence-backed remediation status and useful detection context.
- Avoid duplicate cards for syndicated versions of the same event.
- Preserve uncertainty when source text is limited.

### 4.4 Cyber Business
This section is mandatory in every daily intelligence cycle, even when no material item qualifies.
- M&A, funding/investment/IPO, partnerships, product launches, earnings/results, leadership, hiring/layoffs/restructuring, regulation/policy, significant operations and cyber incidents.
- Show actual publication/announcement date, publisher/source, category and deal/event status.
- Distinguish Rumoured, Announced, Signed, Completed and Terminated where relevant.
- Prioritize company announcements, regulatory filings and credible reporting.
- Filter stock-market noise and low-value duplicate syndication.
- If no qualifying news is verified, say so explicitly and disclose important feed failures/staleness.

### 4.5 CISA KEV
- Keep the full catalogue and useful filters here.
- Clearly distinguish KEV known-exploitation status from CVSS severity, EPSS probability, vendor remediation and the user's patch state.
- A KEV due date is not a vendor patch release date and does not prove an asset is patched.

### 4.6 Detection Queries
- Organize queries by platform/language and purpose.
- Every query must have a unique ID, title, purpose, data source/table, assumed schema/fields, prerequisites, maturity and tuning/interpretation notes.
- Use the same query ID in the daily briefing and query library.
- Never claim tenant compatibility or execution without evidence.

### 4.7 Source Health
- Display active sources and clear states: successful, empty-but-healthy, partially successful, temporarily unavailable, failed, disabled/excluded.
- Show last attempt, last success, records/count where available, and a concise error/limitation.
- Do not treat an empty healthy feed as a failure or a failed feed as evidence that no threat exists.
- Australian ACSC is intentionally excluded; do not re-add it as an active or failing source unless the user explicitly changes this requirement.

## 5. Intelligence collection and evidence rules

### Plain-English technology explanations — global requirement

Every threat, vulnerability, advisory, KEV record and relevant business/market item must include a short plain-English explanation of the named product, service, platform, library, operating-system component or company whenever it can be identified from reliable evidence. This applies across Overview, Daily Briefing, New Intelligence, Cyber Business, CISA KEV, generated daily artifacts and future intelligence feeds.

Use these consistent prompts:
- **What is it?** Identify the technology in everyday language (for example, Drupal is a website content-management system; 1Password is a password manager; libpcap is a library used to capture network traffic).
- **What does it do?** Explain its practical purpose in one short sentence.
- **Why does it matter here?** Connect the affected or exploited technology to the specific vulnerability, incident or business development where the source supports that connection.

Rules:
- Assume the reader may not recognise product names, package names, acronyms or advisory identifiers. Explain unfamiliar terms on first use.
- Keep the explanation concise, ideally one or two short sentences per field; do not turn cards into product documentation.
- Prefer a curated, source-backed glossary and product/vendor fields from primary advisories. Preserve the exact technical product/component name.
- Explain advisory identifiers separately from the affected technology (for example, a USN is an Ubuntu Security Notice identifier; libpcap is the affected software library).
- Never infer a product's purpose from its name alone. If the role cannot be established, explicitly say the source does not provide enough information and link the source.
- Do not confuse a vendor/company with its specific affected product. Use a company background only for business items and a product explanation for vulnerabilities.
- Apply the same wording and fields to the dashboard UI and generated Markdown snapshots/reports. Do not omit the explanation simply because an item came from a different feed.
- Keep source provenance and uncertainty. Automated glossary matching is contextual assistance, not independent verification of vulnerability impact or asset exposure.

### Technology-background accuracy — permanent data-quality gate

Mandatory for every threat, vulnerability, advisory, KEV record and relevant business/market item in the collector, snapshot, dashboard and generated reports.

**Required output structure:** exactly two fields:
- **What is it?** Concisely identify the actual affected technology, product, package, service or ecosystem.
- **What does it do?** Concisely explain its purpose and how it relates to the reported threat, only where supported by reliable evidence.

**Identification and evidence**
1. Identify the actual technology from the primary advisory, vendor documentation, original researcher report or other reliable source. Use the exact affected product/component/package, not merely a vendor name, broad operating system or unrelated technology mentioned in passing.
2. Cross-check descriptions against primary sources, vendor advisories and original security research. Preserve evidence URLs and distinguish source-confirmed facts from inference.
3. Evaluate headline, category, affected product/vendor, source summary/details and proposed background together. They must be semantically consistent.
4. Specificity precedence: an explicitly named package, library, framework, service or product takes precedence over a broad platform/OS mention. A NuGet/.NET package campaign must not inherit a generic Windows OS description merely because Windows is the payload target.
5. Never infer purpose from a name, category, vendor, URL or incidental keyword. Never use a generic OS/company glossary entry as fallback for an unrelated package, library, framework or service.
6. If the technology or role cannot be confidently identified, use this exact safe fallback: **"Technology details could not be independently verified from the available sources."** Do not fabricate explanations; mark context limited/unverified and retain source links.
7. Automated glossary matching is not source verification. A keyword match alone does not prove that technology is affected.
8. Do not silently rewrite historical records. Review historical corrections through an explicit evidence-backed migration and impact summary.

**Automated quality gate**
- Check semantic consistency across headline, category, affected product, Technology Background and threat description.
- Reject or flag generic descriptions that conflict with a more specific named technology, including Windows/Linux descriptions attached to unrelated packages or cloud services.
- Regression-test NuGet/.NET malware, Windows vulnerabilities, Linux vulnerabilities, network security appliances, cloud security incidents, phishing and supply-chain attacks.
- Test correct identification and safe fallback. Static checks are not proof of source verification.
- Run existing dashboard, collector, frontend-security and detection-query validation. Do not declare complete until applicable checks pass.

**Required regression example**
Headline: "13 Malicious NuGet Packages Turn Fake .NET Job Assessments Into Malware Delivery Traps"

Expected technology: NuGet / .NET.
- What is it? "NuGet is the package manager for the .NET ecosystem."
- What does it do? "It manages third-party packages and dependencies in .NET applications. Malicious packages can abuse this mechanism to deliver malware."

Reject the unrelated description: "A desktop and server operating system" / "It runs applications and manages devices, users, files and system services."

### Global source extraction, summary and data-quality standard — mandatory

Apply to every collected advisory, vulnerability, threat-research item and relevant business story, across every configured feed and every dashboard/report surface. This is a collector-wide rule, not a source-specific exception.

**1. Clean extraction**
- Extract editorial/article content only. Exclude navigation, headers/footers, forms, cookie/consent banners, newsletter prompts, sign-up/login text, contact confirmations, preference-update notifications, advertisements, sponsored copy, related-story widgets and other page chrome.
- Keep the original source URL, publisher, publication date and retrieval timestamp. Do not silently replace source text with generated or inferred content.
- If extraction is contaminated or the page is not readable, mark the enrichment as limited/failed and retain a clearly labelled feed snippet. Never present page boilerplate as technical evidence.
- Apply cleanup to both HTML article extraction and RSS/Atom feed summaries. Preserve technical paragraphs even when they contain product marketing terminology; filter only identifiable boilerplate/promotional content.

**2. Concise, source-grounded summary**
- Show a concise technical summary of approximately 3–5 sentences (or fewer when the source is brief), based only on relevant source statements.
- Prioritise the vulnerability/incident, affected component, attack condition and impact when the source states them. Do not invent missing details or use generic product descriptions as the incident summary.
- Keep full source-derived technical details available separately for analyst inspection. Clearly distinguish an extracted excerpt from an independently authored or analyst-verified summary.
- If there is insufficient relevant source text, say that a reliable summary could not be extracted and link the primary advisory. Do not pad with generic operating-system/company descriptions, marketing text or unrelated page copy.

**3. Correct product and CVE mapping**
- Identify vendor, exact product/component/package, affected versions/branches/builds and CVE relationships independently. A vendor, operating-system distribution, advisory ID or headline is not automatically the affected product.
- Explain advisory identifiers separately from the vulnerable product (for example, an Ubuntu USN is an advisory identifier; the affected component may be MIT Kerberos/krb5).
- For multi-CVE advisories, retain one independently traceable record per CVE wherever evidence permits. Do not copy one CVE's impact, severity, affected versions or fix to all CVEs.
- If the source does not establish the product/CVE/version relationship, show **Unverified / Not established** and identify what evidence is missing.

**4. Remediation accuracy**
- Prefer the authoritative vendor advisory/package security notice for fixed releases, affected release ranges, workarounds and restart/deployment requirements. Link directly to the relevant evidence.
- Keep affected versions separate from fixed versions. State distribution/release-specific package versions only when the source explicitly supports them.
- Never convert an extraction failure or absence of remediation text into **No patch available**. Use the defined **NOT ESTABLISHED** / **No fix confirmed in reviewed sources** semantics unless the vendor explicitly confirms no fix.
- A candidate release extracted automatically remains unverified until exact product, edition, branch/build applicability and deployment are checked. A vendor fix statement is not proof that the user's assets are patched.
- Show practical update/restart/mitigation steps only when the source states them; do not invent commands or operational instructions.

**5. Evidence and validation**
- Preserve per-claim source name, direct URL, publication/update date and evidence-check timestamp. Link vendor advisory, CVE/NVD and CISA KEV separately where applicable.
- Distinguish source-reported facts, automated extraction, analyst assessment and analyst verification. Retrieval success, matching text or a green workflow does not establish factual correctness.
- Add regression tests for common boilerplate phrases (contact confirmations, newsletters, preference notices, cookie banners and advertisements), legitimate technical paragraphs, multi-CVE mapping and source-specific remediation.
- Validate that a record's summary is relevant, free of page chrome, concise and traceable to the linked source. If the check fails, downgrade enrichment quality rather than publishing contaminated text as technical detail.
- Apply the same extraction, summary, mapping and remediation rules to dashboard cards, overview panels, KEV entries, daily snapshots and Markdown reports.

### Source policy
- Use configured public government, CERT, vendor, cloud and reputable research/news sources.
- Prefer primary advisories and company announcements. Use secondary sources for context/corroboration.
- Public feeds are incomplete, can be delayed, rate-limited, paywalled or change format. State collection limitations.
- Do not scrape gated services or bypass access controls. Providers requiring credentials or approval must be integrated only through approved APIs and GitHub Actions secrets after terms are reviewed.
- Keep source URLs, publisher, publication date and retrieval/collection time distinct.


### CVE field-level verification — global mandatory standard

Apply to every CVE in New Intelligence, Overview Critical Vulnerabilities Watch, CISA KEV, Daily Briefing and generated reports. One CVE equals one independently traceable record; never map a product from a headline alone.

- Verify identifier/title and CVE description against CVE.org/NVD; use the exact official title where supplied. Never truncate official titles in visible cards or tables.
- Verify CVSS version, base score, vector and metric source against NVD; preserve unavailable, unscored, disputed and lookup-failed states without inventing a value.
- Verify KEV membership directly against the CISA KEV catalogue. KEV membership is a known-exploitation signal, not a CVSS score and must not overwrite CVSS severity.
- Verify vendor/product and affected version ranges against the vendor advisory and, where useful, NVD CPE data. If evidence is missing or conflicting, label the field **Unverified** and flag the mismatch.
- Record source URL and field-level status for product, official title, CVSS, KEV, affected versions and fix/mitigation. Use only **Verified (source)** or **Unverified** in analyst-facing records; analyst verification must be separately recorded if introduced.
- Keep vendor advisory extraction distinct from verified remediation. State **No patch available** only when the vendor explicitly confirms no patch. Otherwise use **No fix confirmed in reviewed sources** and provide source-backed compensating controls only.
- A KEV-listed CVE must receive high operational attention, but do not falsify its CVSS severity. Display a separate Known Exploited / KEV indicator. A CVSS 9.0 score maps to Critical using the applicable CVSS version's severity classification.
- Do not assume that a CVE in a multi-product headline affects every named product. One CVE-to-product mapping per evidence-supported relationship; explicitly flag unresolved or contradictory mappings.
- Automated extraction, title matching and static validation do not constitute source verification. Missing vendor evidence remains Unverified.

### CVE, severity and exploitation
- Do not fabricate a CVE or attach one to a threat without source support.
- CVSS is technical severity; record its version, score and source when available.
- EPSS is an estimate of exploitation probability over the next 30 days, not evidence of exploitation.
- CISA KEV membership is a separate known-exploitation signal.
- Vendor/researcher reports of exploitation must be attributed to that source and not silently upgraded to independently verified fact.
- Asset exposure, business criticality, compensating controls and patch state are unknown unless an authorized inventory/telemetry source is integrated.

### IOC policy
- IOC extraction produces **candidates**, not confirmed malicious indicators, blocklists or attribution.
- Preserve source and context; do not infer reputation or maliciousness.
- Defang indicators in display where appropriate.
- Never auto-block, enrich through unapproved services or send candidate indicators to production tools without explicit approval.

### Remediation evidence
Use the evidence states defined in [REPORTING_STANDARD.md](REPORTING_STANDARD.md) and [INTELLIGENCE_QUALITY.md](INTELLIGENCE_QUALITY.md). In short:
- Separate fixed releases from affected releases and mitigations.
- Automated extraction is not analyst verification.
- A candidate version remains unverified until product/edition/branch applicability is checked.
- "No fix found in reviewed material" is not the same as "vendor confirms no fix".
- A generic CISA KEV requiredAction is not automatically a vendor patch.
- Never invent commands, KBs, fixed builds or workaround procedures.

## 6. Detection engineering rules

### Maturity labels
Use only:
- **Draft**
- **Schema-checked**
- **Syntax-validated**
- **Lab-tested**
- **Production-approved**
- **Retired**

Meanings:
- Draft: not validated in target tenant.
- Schema-checked: table and field assumptions checked against target tenant/schema.
- Syntax-validated: parsed by the appropriate official parser/editor.
- Lab-tested: positive and negative test events executed and reviewed.
- Production-approved: reviewed, tuned, owned and approved for deployment.
- Retired: no longer recommended; retain a reason/history.

Static lint is not an official Kusto/SPL/YARA-L parser, tenant-schema validation, lab test or production approval.

### Query requirements
- Prefer Microsoft Sentinel KQL for the daily briefing when a meaningful customer-side query is possible.
- Add SPL or Google SecOps YARA-L when relevant and useful.
- Declare required telemetry, table names, fields, time window and assumptions.
- Explain what a match means and what it does not prove.
- Include tuning/false-positive notes where possible.
- Never claim a query detects provider-side activity if the customer has no relevant telemetry.
- Do not create a misleading placeholder when no useful query is possible.
- Full KQL in Markdown reports must use exact ```kql opening fences and matching ``` closing fences. Each query gets its own titled block. No mismatched tilde/backtick fences.

## 7. UI/UX and accessibility standards

- Professional security-operations dashboard; information density must serve analyst decisions.
- Consistent typography, spacing, labels, dates, statuses and link behavior.
- Keep navigation stable and concise.
- Avoid redundant badges, repeated metadata, unnecessary panels, decorative widgets and excessive card nesting.
- Show detailed technical context adjacent to the relevant threat; do not force users to revisit sources for basic facts that can be reliably extracted.
- Keep remediation adjacent to the vulnerability/threat.
- Use compact tables where comparison helps; use individual sections/cards where long detail is needed.
- Ensure responsive behavior on mobile, tablet and desktop; no horizontal overflow for core views.
- Provide keyboard access, visible focus, accessible names, semantic landmarks, adequate contrast and reduced-motion support.
- Test date navigation, latest/next/last controls, filters, search, archive selection, expandable query blocks and external links.
- Do not call a visual or accessibility audit complete based only on static checks. Browser and manual testing are required.

## 8. Security and repository protection

### Repository posture
- Repository is intentionally **public** for now; the GitHub Pages site must remain publicly accessible.
- Do not change repository visibility without the user's explicit request.
- Do not commit secrets, API keys, tokens, passwords, private keys, `.env` files, customer data, internal incident details, confidential indicators or private asset inventories.
- If a secret is exposed, stop, revoke/rotate it, remove it from active code/history as appropriate, and disclose the incident. Deleting a visible line alone does not invalidate a leaked credential.

### GitHub Actions
- Use least-privilege workflow permissions. Keep read-only defaults; grant write/deploy permissions only to the specific job that needs them.
- Keep third-party actions pinned/maintained and use supported Node runtimes.
- Do not expose secrets to untrusted pull-request code.
- Validate external content before rendering; treat all feed/article text as untrusted.
- Preserve collector SSRF safeguards, HTTPS-only source handling, redirect validation and safe frontend rendering.
- Keep GitHub Pages deployment on the intended workflow path; avoid parallel deploy races.
- Never add production response actions or privileged connectors without explicit approval and a threat model.

### Branch and change policy
- `main` is the sole working branch unless the user explicitly requests otherwise.
- Protect `main` against deletion and force-pushes where possible. Do not require pull requests until the direct-push daily automation is safely adapted or a documented bypass is configured.
- Make focused, reviewable commits with descriptive messages.
- Do not delete or rewrite project history, files, workflows or datasets without confirming dependencies and user intent.
- Do not create dozens of branches. Clean up temporary branches after use when authorized.
- Never say a change is complete until the write result and relevant validation are confirmed.

## 9. Canonical repository artifacts

| Path | Responsibility |
|---|---|
| `index.html` | Dashboard interface and client-side rendering |
| `scripts/collect_threat_intel.py` | Public-source collection, enrichment, normalization, health tracking and generated artifacts |
| `scripts/validate_dashboard.py` | Dashboard/collector/data regression validation |
| `scripts/validate_detection_queries.py` | Detection query metadata and KQL structural checks |
| `scripts/validate_detection_formats.py` | SPL and YARA-L metadata/structure checks |
| `scripts/validate_frontend_security.py` | Frontend security regression checks |
| `.github/workflows/daily-threat-intel.yml` | Daily collection and canonical Pages deployment |
| `.github/workflows/dashboard-quality-watch.yml` | Scheduled dashboard/frontend quality watch |
| `.github/workflows/detection-query-ci.yml` | Query and repository quality checks |
| `intel/latest.json` | Pointer to latest snapshot/report artifacts |
| `intel/snapshots/YYYY/MM/DD.json` | Dated structured intelligence snapshot |
| `intel/daily/YYYY/MM/DD.md` | Collector-generated daily artifact, where generated |
| `intel/source-health-state.json` | Per-source health history/state |
| `detection-queries/` | Curated query library |
| `detection-queries/generated/` | Generated candidate hunts |
| `reports/YYYY/MM/DD.md` | Analyst-facing daily briefing archive; verify automation before claiming auto-publication |
| `README.md` | Public project introduction and quick reference |
| `ARCHITECTURE.md` | System architecture, trust boundaries and limitations |
| `REPORTING_STANDARD.md` | Detailed daily report format and remediation rules |
| `INTELLIGENCE_QUALITY.md` | Evidence and data-quality policy |
| `PHASE1_PHASE2_STATUS.md` | Historical implementation/status record; may contain retired feature history |

Do not assume a path or workflow still exists based only on this table; inspect the current `main` tree before modifying it.

## 10. Mandatory operating instructions for the AI assistant

When acting on this repository, follow these instructions as if they were the project system prompt:

1. **Read first:** Read this master file and the relevant existing code/docs/workflows before changing anything. For reporting changes, also read `REPORTING_STANDARD.md` and `INTELLIGENCE_QUALITY.md`.
2. **Inspect actual state:** Fetch the current `main` version and relevant workflow runs/files. Do not rely on stale chat context or assume previous work is still present.
3. **Clarify only blockers:** If a requirement is materially ambiguous or destructive, ask one concise question. Otherwise make the smallest safe implementation consistent with this document.
4. **No pretend execution:** Do not claim to have browsed, tested, deployed, merged, committed, or changed a setting unless the relevant tool result confirms it.
5. **Plan before broad changes:** For multi-file work, identify affected files, dependencies, expected behavior and validation before writing.
6. **Preserve working features:** Do not remove or redesign working functionality outside the user's request. Check all callers, data contracts, workflows and validators before deleting code.
7. **No feature creep:** Do not add agentic AI, autonomous agents, dashboards, pages, widgets, panels, connectors, frameworks or new dependencies unless the user explicitly approves them.
8. **Evidence discipline:** Never invent threat facts, CVEs, IOC reputation, exploit status, fixed versions, business deals, dates, query maturity or source success. Show unknown/failed/not verified states honestly.
9. **Security first:** Treat feed content as hostile input. Preserve SSRF, XSS, URL validation, escaping, secret-handling and least-privilege controls.
10. **Validate:** Run or trigger the relevant validators/workflows after edits. Inspect failures and fix regressions before declaring completion.
11. **Verify deployment:** For website changes, verify the Pages workflow and deployed artifact/source revision where possible. A commit alone is not proof the live website changed.
12. **Report honestly:** Summarize exactly what changed, files/commit, checks passed/failed, remaining limitations and whether the live site was verified. Keep the response concise.
13. **Ask before consequential actions:** Do not change repository visibility, delete branches/history/data, rotate credentials, change secrets, enable production integrations or introduce automated response without explicit user approval.
14. **One source of truth:** Update this document when the user approves a durable requirement change. Keep detailed standards in their dedicated files and link them here rather than allowing conflicting copies.

## 11. Reusable prompts for future work

### A. General repository implementation prompt
"Act as the senior engineer and security architect maintaining the Global Cyber Intelligence Command Center. Read `MASTER_REQUIREMENTS.md`, `ARCHITECTURE.md` and all relevant standards/code/workflows first. Inspect the current `main` branch before editing. Implement only the requested change, preserve all existing approved behavior and retired-feature decisions, apply secure coding and least privilege, update relevant tests/docs, run the appropriate validators, inspect workflow results and verify deployment when applicable. Do not claim success without evidence. Report changed files, commit, checks, deployment status and remaining limitations."

### B. Daily intelligence and briefing prompt
"Produce the Global Cyber Threat Radar briefing using the current reporting window and `REPORTING_STANDARD.md`. Prioritize verified developments from the previous 24 hours, extending to 72 hours when quiet; carry forward older material only when still operationally relevant and label it with its original date. Use primary sources first, corroborate material claims, distinguish publication date from collection time, include threat detection and concrete remediation side by side, and include the mandatory Cyber Business section. Never invent missing details. State source failures and uncertainty. Use matching Q# references and correctly fenced KQL blocks. Validate the final report against the reporting and intelligence-quality standards before publishing."

### C. Dashboard UX/security audit prompt
"Act as a senior security product designer, SOC analyst, accessibility reviewer and frontend security auditor. Audit the live dashboard and current source. Check every navigation view, content hierarchy, responsive layout, date controls, filtering/search, source links, remediation visibility, data freshness, empty/error states, keyboard/focus behavior, contrast, reduced motion, XSS/URL handling and browser-console errors. Keep Critical Vulnerabilities Watch on Overview only. Do not restore retired toolkit or actor/campaign pages. Separate verified defects from recommendations. Prioritize issues by severity and implement only after the requested scope is clear; run regression checks and verify the live deployment."

### D. Workflow/automation audit prompt
"Inspect every current GitHub Actions workflow and its triggers, permissions, secrets, concurrency, action versions, schedules, artifact paths, commit/push behavior, retries, validation gates and deployment ordering. Confirm daily collection is 09:00 IST and distinguish it from the 10-minute quality watch. Check that the daily workflow commits the intended paths and deploys the latest `main` SHA. Identify duplicate schedules, race conditions, missing reports, stale data and excessive permissions. Do not change the schedule or require PRs until direct-push automation compatibility is addressed. Implement only approved fixes and verify actual workflow runs."

### E. Detection engineering prompt
"Act as a senior detection engineer for Microsoft Sentinel, Splunk and Google SecOps. For every proposed detection, document purpose, threat behavior, telemetry prerequisites, tables/fields, assumptions, time window, query, expected matches, false positives, tuning and response guidance. Label maturity honestly: Draft, Schema-checked, Syntax-validated, Lab-tested, Production-approved or Retired. Never claim parser, tenant or production validation unless actually performed. Provide positive and negative test cases before promoting maturity."

### F. Change-control prompt
"Before a change, identify the exact user requirement, affected files, dependencies, risks and rollback. Prefer minimal diffs. Do not refactor unrelated code. After the change, run relevant validators, inspect workflow logs, verify generated artifacts and live deployment if applicable. If validation fails, fix or revert before reporting. Record durable approved decisions in `MASTER_REQUIREMENTS.md` and the relevant detailed standard."

## 12. Definition of done

A task is complete only when all applicable conditions are met:
- The requested behavior is implemented in the intended files.
- Existing approved features and security boundaries remain intact.
- Relevant automated validators pass.
- Workflow run results are checked, not assumed.
- Generated data and report paths are verified.
- Website changes are confirmed in the deployed Pages artifact/live site when deployment is in scope.
- Documentation is updated where a durable requirement or operational behavior changed.
- Remaining limitations are stated clearly.
- The user receives a concise, evidence-based completion summary.

## 13. Current known limitations and open verification items

- The dashboard is public and hosted on GitHub Pages; the source repository remains public by current decision.
- No authenticated SIEM, EDR, asset inventory, patch-management, ticketing or response system is connected.
- No automated containment/blocking/production remediation is performed.
- Static KQL/SPL/YARA-L checks do not prove official parser acceptance, tenant schema compatibility or production effectiveness.
- Browser-driven cross-device testing, full manual accessibility review and screen-reader validation remain separate from static CI.
- The daily collector workflow currently commits `intel/` and generated query artifacts; automated publication of `reports/YYYY/MM/DD.md` must be implemented and verified before being described as complete.
- Source health and feed counts must be rechecked on actual runs; historic successful counts are not guarantees of future health.

---

## Change log
- **2026-11-25:** Created as the controlling project requirements and operating-rules reference. Consolidates current scope, retired features, daily schedule, reporting expectations, security rules, AI prompts and definition of done.
