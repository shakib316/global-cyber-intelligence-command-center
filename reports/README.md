# Daily Cyber Threat Radar Reports

Daily reports are stored by date in `YYYY/MM/DD.md` using the Asia/Kolkata timezone.

Each report contains:

1. **Yesterday's threats** — concise table covering threat, description, CVE, affected products, urgency/exploitation, detection, remediation, Microsoft Sentinel KQL, confidence and sources.
2. **Today's threats** — per-threat summary, detection guidance, remediation, KQL, verified indicators/TTPs and source links.
3. **Action checklist** — prioritised operational steps.
4. **Verification note** — quiet-day disclosure and research limitations.

KQL queries are illustrative unless validated against the organisation's actual Sentinel tables and field mappings. Never treat an IOC match alone as proof of compromise. CVEs, CVSS, KEV status, affected versions, exploit claims and IOCs must be source-verified.

Reports are append-only by date; do not silently overwrite a prior day's briefing.
