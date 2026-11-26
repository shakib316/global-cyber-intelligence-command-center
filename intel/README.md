# Intelligence data and collection

The collector combines public government, vendor and research sources. It records source health, publication timestamps, source URLs, CVEs, topic signals and candidate indicators.

## Collection behavior

- Threat intelligence uses a rolling 72-hour collection window.
- CISA KEV additions are tracked separately over seven days.
- Cyber business and market developments use a wider seven-day window.
- Duplicate source URLs are consolidated.
- Australian ACSC remains intentionally excluded.
- Source failures and partial collection remain visible; an empty feed is not proof that no threats occurred.

## Repository artifacts

- `intel/latest.json` — pointer to the latest snapshot and daily report.
- `intel/daily/YYYY/MM/DD.md` — collector-generated daily report and source-health summary.
- `intel/snapshots/YYYY/MM/DD.json` — structured intelligence, provenance, source health, KEV and candidate IOC data.
- `reports/YYYY/MM/DD.md` — analyst-facing daily briefing archive.
- `detection-queries/generated/YYYY/MM/` — generated candidate IOC hunts, created only when candidates are available.

## IOC and detection policy

IOC extraction is limited to values near explicit IOC language in source material. These are candidates, not confirmed malicious indicators or blocklists. Verify the source, exact value, age and context before use. Behavior hunts are separate from IOC hunts and must not imply actor or campaign attribution without primary-source evidence.

Detection queries retain explicit maturity labels. Static repository checks do not establish tenant schema compatibility, successful parsing by vendor tools, behavioural correctness or production effectiveness.

## Credentials and limitations

ThreatFox, AlienVault OTX, GreyNoise and Shadowserver may require keys, registration or provider approval; they are not silently scraped. Configure credentials as GitHub Actions secrets only after reviewing provider terms. Public feeds are not exhaustive and may change, fail or be delayed. No automatic blocking or response actions are performed.
