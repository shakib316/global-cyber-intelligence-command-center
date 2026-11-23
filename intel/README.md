# Automated Threat Intelligence Collection

Daily collection combines public government, vendor and research sources. The collector records source health, publication timestamps, URLs, CVEs, topic signals and candidate IOCs.

## Configured sources

CISA KEV JSON; CISA All and ICS Advisories; CERT-In India public advisory index; Microsoft MSRC; AWS Security Bulletins; Splunk Security Advisories; UK NCSC; Canadian CCCS; Australian ACSC; CERT-EU; SANS Internet Storm Center; Cisco Talos; Palo Alto Unit 42; Google Threat Intelligence / Mandiant; BleepingComputer; and The Hacker News.

The collector retains dated items from the last 72 hours plus undated CERT-In index entries. KEV additions are separately reported for seven days. Duplicate URLs are consolidated.

## Artifacts

- intel/daily/YYYY/MM/DD.md — readable report and source health.
- intel/snapshots/YYYY/MM/DD.json — structured evidence and provenance.
- detection-queries/generated/YYYY/MM/ — candidate IOC KQL only when candidates are extracted.

## IOC and detection policy

IOC extraction is limited to values near explicit IOC language in source summaries. These are candidates, not confirmed malicious indicators; verify source, exact value, age and context before use. Behavior hunts are separate from IOC hunts and are not attributed to campaigns unless primary reporting supports that link. Queries remain Draft until schema-checked, syntax-validated, lab-tested and approved.

## Credentials and limitations

ThreatFox, AlienVault OTX, GreyNoise and Shadowserver may require keys, registration or provider approval; they are not silently scraped. Configure credentials as GitHub Actions secrets only after reviewing terms. Public feeds are not exhaustive and may change or fail. A quiet report does not prove no threats occurred. No automatic blocking or response actions are performed.


## Current dashboard data behavior

- Threat intelligence uses a rolling 72-hour collection window.
- Cyber business and market developments use a wider 7-day window to avoid an empty feed on quieter days.
- The dashboard renders the latest snapshot referenced by `intel/latest.json`; source failures remain visible in source health.
