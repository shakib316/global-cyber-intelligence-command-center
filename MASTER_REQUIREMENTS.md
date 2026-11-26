# MASTER_REQUIREMENTS.md
# Global Cyber Intelligence Command Center — Master Requirements & Operating Rules

**Status:** Controlling project reference  
**Repository:** `shakib316/global-cyber-intelligence-command-center`  
**Default branch:** `main`  
**Live website:** https://shakib316.github.io/global-cyber-intelligence-command-center/  
**Last reviewed:** 25 November 2026

This document is the single high-level reference for the product's purpose, scope, user requirements, operating schedule, quality standards, AI-assistant instructions and repository-maintenance rules. Read it before making material changes.

## Global editorial quality contract — mandatory for every intelligence item

- **What is it?** must define the actual technology, product, framework, protocol, package manager, operating-system component or vulnerability class. Add one concise incident-context sentence when supported. Do not substitute the headline, discovery statement or attack summary for a definition.
- **What does it do?** must explain the technology's normal purpose or function, then clarify its relevance to the reported event when evidence supports it. Do not put exploit mechanics here as a substitute for the technology's normal function.
- Technology definitions may come from the reviewed incident article or a separate authoritative primary source. Store the exact documentation URL in the item's technology-background provenance and show it among the maximum three source links.
- Curated definitions are permitted only when they have been checked against authoritative documentation. A term match alone must not be presented as evidence that a product is affected or vulnerable.
- If no reliable definition is available, use the explicit **Not established in reviewed sources** fallback for both questions. Never fill the fields with a generic incident summary or an inferred product capability.
- For non-technology business developments, both fields are **Not applicable**. For a technology product launch, define the technology only when source evidence supports it.
- **Technical details** must contain up to four distinct, concise, source-supported facts about scope, affected components, mechanisms, execution flow, impact or relevant counts. Exclude repeated headline/lead summaries, duplicate facts, author quotations, boilerplate and truncated article fragments. Prefer analyst-written paraphrases over long quotations.
- CVSS, EPSS, publication metadata, publisher and status belong in concise labels where relevant, not padded technical-detail paragraphs.
- **Sources** must use meaningful publisher/domain labels with direct links, never generic “Source 1 / Source 2” numbering. Keep no more than three.
- Apply these semantics in New Intelligence, Cyber Business, CISA KEV, overview vulnerability cards, generated daily reports and historical records. Historical cards should use the same source-backed fallback/catalogue logic where the original snapshot lacks the newer structured fields.
- Regression tests must include both a positive definition case (NuGet) and a negative case where an incident sentence merely calls something a vulnerability (Fragnesia/XFRM), plus deduplication and four-line limits.

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

### Daily collection and AI-enrichment sequence
1. GitHub Actions starts collection at 09:00 IST on `main`.
2. Collector retrieves configured public advisories, research feeds, KEV and business-news sources; records source health and creates the current-day structured collection.
3. Static snapshot/dashboard and detection-query checks run against the collected data.
4. The collector commits the raw/normalized collection to the isolated `intel-staging` branch. It must not update `main` or deploy GitHub Pages.
5. The scheduled ChatGPT AI-enrichment task (approximately 10:15 IST) reads the staged snapshot, reviews every distinct current-day item against direct sources and authoritative references, enriches and deduplicates the content, and quarantines unsupported items with reasons.
6. Only after all required enrichment and validation succeeds does the task publish the current-day enriched snapshot, daily report and latest pointer to `main` in one atomic Git commit. This main-branch push triggers the separate GitHub Pages deployment workflow.
7. Verify the deployment and report collection, source-health, enrichment, quarantine, validation and deployment counts/statuses. If any critical step fails, do not advance the latest pointer or publish partial content.
8. Quality Watch continues independently on its configured schedule and workflow events.

**Important implementation distinction:** `intel-staging` is a temporary raw/normalized staging branch, not the public dashboard source. The website reads only `main`. Historical records before 27 November 2026 are read-only for this new pipeline. The collector does not currently retain complete raw article bodies for every feed; source URLs, feed metadata, normalized item fields and source-health results are the evidence baseline. Analyst-facing `reports/YYYY/MM/DD.md` and collector-generated `intel/daily/` are distinct paths; the ChatGPT task must update only the current day's paths.

### Schedule maintenance rules
- Preserve the daily 09:00 IST collection unless the user explicitly changes it.
- Do not confuse the 10-minute Quality Watch with collection frequency.
- Do not create overlapping Pages deployments or competing scheduled collectors.
- After changing schedules, inspect the workflow YAML and verify the next successful run.
- A green workflow means its configured steps passed; it does not prove every feed or intelligence claim is complete.

## Global intelligence item format

Every threat, vulnerability, advisory, incident and cybersecurity business/industry news item must use the six-part format in [REPORTING_STANDARD.md](REPORTING_STANDARD.md): Title; necessary Labels; Technology background with “What is it?” and “What does it do?”; Technical details limited to four concise lines; Remediation status; and no more than three Sources links. Technology background must be explicitly supported by reviewed source material. If not established, state that; never invent a product function. For non-technology business developments, mark technology background not applicable.

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

### Source policy
- Use configured public government, CERT, vendor, cloud and reputable research/news sources.
- Prefer primary advisories and company announcements. Use secondary sources for context/corroboration.
- Public feeds are incomplete, can be delayed, rate-limited, paywalled or change format. State collection limitations.
- Do not scrape gated services or bypass access controls. Providers requiring credentials or approval must be integrated only through approved APIs and GitHub Actions secrets after terms are reviewed.
- Keep source URLs, publisher, publication date and retrieval/collection time distinct.

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
