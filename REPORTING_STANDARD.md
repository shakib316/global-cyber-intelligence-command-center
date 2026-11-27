# Daily Global Cyber Threat Radar — Master Feedback & Reporting Standard

**Status:** Master standard. Apply to every subsequent daily briefing, dashboard/business-news update and GitHub report. This supersedes inconsistent formatting in older drafts. Use 23 November 2026 as the visual reference for the threat table and concise threat write-ups; keep facts current and never copy stale content.

## Mandatory global item format — applies everywhere

Apply this exact six-part structure to every threat, vulnerability, advisory, incident and cybersecurity business/industry news item in dashboard cards, daily reports, KEV views and generated intelligence:

1. **Title**
2. **Labels** — include only labels needed to identify status, source, date, CVE or category.
3. **Technology background**
   - **What is it?**
   - **What does it do?**
   - State only facts explicitly supported by reviewed, source-linked material. If the source does not establish the technology's purpose/function, say **Not established in reviewed sources**. Never infer capabilities from a product name, headline, vendor, CVE mapping or general industry knowledge.
   - For non-technology business developments, state **Not applicable** rather than inventing a technology description.
4. **Technical details** — no more than four concise lines/sentences, with only source-supported facts.
5. **Remediation status** — use the evidence states below for vulnerabilities/threats. For business news, state **Not applicable — business/industry development**.
6. **Sources** — no more than three direct, relevant links; prefer primary sources.

This global six-part format supersedes older per-card/per-item layouts and longer narrative templates below. It does not authorize removal of useful detection-query libraries, source-health information, collection metadata or other standalone dashboard functions; those remain separate product-level resources, not extra sections inside an intelligence item.

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

## 1. Reader and editorial principles
- Write for a Security Engineer with 7 years' experience across SIEM/SOAR, Google SecOps, Splunk, Microsoft Sentinel, detection engineering, cloud security and incident response.
- Make the briefing concise, technically useful and scannable. Use short, consistent labels, compact paragraphs, bullets and tables. Avoid generic padding, vague remediation, repeated facts and unexplained acronyms.
- Prioritise the last 24 hours since the previous briefing; do not widen the collection window during quiet periods. Carry older items only when exploitation, remediation or business impact remains active, and label them **Carry-forward** with original date.
- Deduplicate syndicated reports and multiple sources about the same event. Prefer primary vendor/government/company sources; add independent corroboration for material claims.
- Distinguish confirmed facts, vendor statements, researcher observations, media reporting, analyst assessment and unverified extortion-group claims. Never present a leak-site listing as proof of compromise.
- Include India/APAC relevance when supported. Explain acronyms on first use or in a short glossary.
- Show local generation time and exact coverage window in Asia/Kolkata (IST).

## 2. Fixed daily briefing structure

### 1) YESTERDAY'S THREATS — one compact table
Use the 23 Nov reference layout and keep this table first. Keep one row per distinct incident/vulnerability, with these columns in this exact order:
1. Threat/name
2. Short description
3. CVE(s)
4. Affected products/versions
5. Urgency / verified exploitation / KEV status
6. How to detect (specific telemetry, fields and behaviour)
7. How to fix (specific patch, version, workaround or containment)
8. Microsoft Sentinel KQL detection query
9. Source links / confidence

Formatting rules:
- Keep each cell short and informative; use short bold lead-ins for status/version where useful.
- No CVE: write **None disclosed**. Unknown version: **Not disclosed**. Do not invent.
- Query cell should show a compact query identifier and one-line purpose, e.g. **Q1 — egress IOC hunt**. The full query lives in the expandable query library below, not a huge code block inside the table.
- Every threat row must have useful detection and concrete remediation. If there is no meaningful customer-side detection (e.g. third-party exfiltration), say so plainly; never imply KQL can detect activity outside the tenant.
- Keep source links close to the claim and confidence specific to the evidence.

### 2) TODAY'S THREATS — concise, individually structured write-ups
Use a separate heading for each distinct threat. Keep a consistent order and labels:
- **Date / status**
- **Impact**
- **Affected products / regions**
- **CVE / severity / KEV** (only verified; otherwise say not disclosed/not confirmed)
- **Detect** (logs, event IDs, fields, behaviours; name telemetry prerequisites)
- **Fix / contain** (specific version, configuration, isolation or credential action; if no fix exists, state **No patch available** only when verified; otherwise **No fix confirmed in reviewed sources**)
- **KQL** (query ID and purpose; full query in expandable query library)
- **Confidence / attribution** (separate confidence in event from confidence in attribution)
- **Sources**
Use concise threat cards/sections, not long narrative essays. Include relevant ransomware/breach, APT/ATT&CK and AI-enabled activity only when material and sourced. Label carry-forward stories clearly and do not misrepresent their original publication date as new.

### Detection query library — nested under Today's Threats
- Place full queries in separate expandable details blocks with a short summary: Q1 — product: detection purpose.
- Each query block contains: purpose, data source/table, assumed schema, query maturity, KQL code and interpretation/tuning notes.
- Reference the same Q-number in the threat table and threat write-up. No orphan query and no threat with a dangling query reference.
- Use Microsoft Sentinel KQL as default. Add Google SecOps YARA-L or Splunk SPL only when it materially helps.
- Never invent table/field names as if tenant-confirmed. Clearly label assumed schemas and use illustrative queries when no tenant schema is available.
- If no meaningful query is possible, state why and do not create a misleading placeholder.
- Query maturity must be honest: **Draft**, **Schema-checked**, **Syntax-validated**, **Lab-tested**, **Production-approved** or **Retired**. Static lint is not Kusto parser validation, tenant validation, lab testing or production approval.
- Every full Sentinel query MUST be rendered as a fenced code block using the exact opening line ` ```kql ` and the exact closing line ` ``` ` on its own line. Opening and closing delimiters MUST match; a tilde fence closing a backtick fence is invalid. Do not use plain text, inline backticks, indented code, `~~~kusto`, or unlabeled fences for full KQL. Put each query in its own clearly titled/expandable block directly within the Today's Threats section. The table may contain only a short Q# reference and purpose. Before publishing, assert that every opening ` ```kql ` has a matching closing ` ``` ` and that no `~~~` fence remains in the report. Keep query text readable and free of Markdown table-pipe corruption.

### 3) CYBERSECURITY BUSINESS & INDUSTRY NEWS — mandatory daily section
This section must appear every day, even when no qualifying item is found.
- Search the previous 24 hours first; use the same strict rolling 24-hour UTC discovery window; do not widen it to 7 days. Clearly show the publication/announcement date.
- Cover cybersecurity company M&A, funding/investment/IPO, partnerships, product launches, earnings/financial results, leadership, hiring/layoffs/restructuring, regulation/policy and material industry operations.
- Prioritise company-confirmed announcements, SEC/stock-exchange filings, regulators and reputable reporting. Cross-check major deal values and label rumours as **Rumoured**, signed agreements as **Signed**, and completed transactions as **Completed**.
- Each item uses short labels: **Category**, **Status**, **What happened**, **Why it matters**, **Confirmed vs forecast**, **What to watch**, **Sources**.
- Include security industry implications, customer/vendor impact and strategic relevance. Keep stock-price chatter out unless tied to a material company event.
- If no material news qualifies, explicitly write **No material verified business developments found in the review window** and name key feed/source failures. Do not omit the section.
- The dashboard's Cyber Business & Market News panel and the daily Markdown briefing must both refresh from the daily collector. Verify business_items collection, count, dates, publisher/source and source-health status. Do not mark the business section current if feeds failed or are stale.

### 4) ACTION CHECKLIST
Split into **Immediate — today** and **This week**. Every action must map to an item above. Use concrete verbs and identify the asset/team/telemetry or decision required. No generic “follow vendor instructions” wording.

### 5) QUIET-DAY / VERIFICATION NOTE
- State whether the day is quiet or material.
- List important source failures/unavailable pages and what was verified through mirrors or secondary sources.
- Separate known facts from unknown scope, attribution, affected versions and IOCs.
- Explicitly say when no meaningful fix, IOC or KQL is available.
- Add a short acronym glossary only when needed.

## 3. Global remediation evidence model — mandatory for every vulnerability surface

Apply the same remediation semantics to New Intelligence, Overview / Critical Vulnerability Watch, CISA KEV, daily briefing cards and any vulnerability detail view.

### Allowed remediation states
- **FIX VERIFIED** — only when an analyst has checked the authoritative vendor advisory, exact product/edition, affected branch/build, fixed release and applicability. Store analyst verification, checked timestamp, fixed version/build and direct source.
- **MITIGATION VERIFIED** — vendor/analyst-confirmed workaround with exact configuration/action, scope, limitations and rollback/operational risks. Never label this as fixed.
- **SPECIFIC ACTION — VERIFY** — concrete source-derived command, configuration change, package or version candidate exists, but exact applicability or deployment is not analyst-verified. Show amber status.
- **CANDIDATE RELEASE — VERIFY** — version wording extracted automatically. Display as candidate only, with source link and explicit non-verified label. Never render green or imply fixed.
- **VENDOR REPORTS NO FIX** — only when the reviewed authoritative source explicitly says no patch/fix is available. Show containment and next review guidance where available.
- **WORKAROUND — PORTAL ACCESS** — vendor confirms a workaround exists but instructions are gated. Do not invent the procedure.
- **NOT ESTABLISHED** — no specific remediation found in reviewed material, or the source was not retrieved. State that this does not prove no fix exists; distinguish not-reviewed from reviewed/no-fix-found.

### Evidence and source rules
- CISA KEV establishes known exploitation/catalogue status; its generic requiredAction is not a product-specific patch. Always seek the linked vendor advisory for remediation. Never infer that absence of a fix in KEV means no vendor fix exists.
- Automated extraction is not analyst verification. A source-linked vendor statement or candidate version must remain amber until applicability is verified.
- A green remediation status is reserved for analyst-verified fixed release or mitigation. Red is reserved for vendor-confirmed no-fix status, not CVSS severity.
- Keep vulnerability severity (CVSS and its version/source), exploitation status (CISA KEV/vendor/researcher), EPSS estimate and remediation status as separate fields/indicators.
- Show affected product/edition and affected versions separately from fixed versions. If unknown, say **Not disclosed / Not established**; do not infer.
- For each CVE in a record with multiple CVEs, preserve its separate identity and map affected/fixed versions and mitigations per CVE where sources allow. If mapping is unavailable, explicitly state that the shared record contains multiple CVEs and each requires individual review.
- Separate permanent fixes from temporary mitigations. Include prerequisites, impact, rollback and exposure conditions when source-supported.
- Show source publisher, direct advisory link, source publication/update date and last evidence-check timestamp. Link vendor advisory, CVE/NVD and CISA KEV distinctly where applicable.
- Do not use generic filler such as “apply mitigations in accordance with vendor instructions” as the remediation. If no specific guidance was found, say so plainly and link the best source.
- Detection guidance must name required telemetry and distinguish a useful hunt from proof of exploitation. State when customer-side detection is not possible or is provider-side only.

## 3. Consistency and readability checks — mandatory before publishing
- Dates: report title, generation timestamp, coverage window, incident date, source publication date and carry-forward labels agree.
- Threats: CVE, CVSS version/score, affected versions, fixed version, KEV status, due date and exploit status do not contradict one another.
- Sources: each material claim has a direct source; primary sources are preferred; link text identifies the publisher/event.
- Detection: telemetry required by the query is named in the write-up; query ID matches the correct threat; no false claim that a query was executed.
- Remediation: actionable and product/version-specific where available; distinguish a fix from a mitigation and a due date from patch availability.
- Labels: use consistent concise labels and confidence vocabulary; do not use “critical” as a generic adjective without explaining whether it is CVSS, vendor severity or operational urgency.
- Formatting: Markdown table renders; code fences balance; expandable query blocks open/close; no duplicate section numbers; no broken links; avoid excessively wide tables where possible.
- Brevity: remove repeated summaries, unnecessary filler and duplicated IOCs. Keep high-value detail; do not truncate facts needed to act.
- Business news: check business-feed freshness and business_items every day; display event date, source and deal status; report no-news/source-failure state honestly.
- Validate the final rendered Markdown and report file before committing. Keep dashboard business-feed health visible.

## 4. Publishing and daily automation
- Publish one report per date at reports/YYYY/MM/DD.md on main, with IST timestamp. Never overwrite another day's report. If updating the same day's draft, preserve audit history and use an explicit validation/update commit message.
- Keep the dashboard collector and daily workflow running; business-news feeds are part of daily collection and must not be skipped.
- Deliver the briefing in ChatGPT and publish the same day's report to the repository.
- If a feed, GitHub write or validation step fails, disclose it. Never claim full coverage or success from a partial run.
