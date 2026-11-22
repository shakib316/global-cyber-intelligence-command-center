# Detection Query Library

A versioned, technology-categorized library of threat-hunting and detection queries. KQL is the first-class format; SPL and Google SecOps YARA-L can be added alongside it as equivalent implementations.

> **Safety and quality status:** Initial queries are **Draft / needs environment validation**. They have not been executed against your Sentinel workspace or tested against your tenant schemas. The 22-Nov-2026 report contains the source queries copied into this library. The report's threat claims and CVE details are not revalidated by copying its queries; verify threat intelligence independently before operational use.

## Browse by technology

| Category | Folder | Focus |
|---|---|---|
| Windows / Endpoint | [kql/windows](kql/windows/) | Defender endpoint process telemetry, browser and PowerShell behaviour |
| Identity | [kql/identity](kql/identity/) | Entra ID privileged activity and application consent |
| Linux | [kql/linux](kql/linux/) | SSH authentication failures and brute-force hunting |
| Firewall / Network | [kql/firewall](kql/firewall/) | Rare or unusual destination hunting from firewall telemetry |
| Cloud / Containers | [kql/cloud](kql/cloud/) | Kubernetes audit activity, secrets and pod creation |
| Virtualization | [kql/virtualization](kql/virtualization/) | VMware vCenter syslog hunting |
| Asset inventory | [kql/asset-inventory](kql/asset-inventory/) | Software inventory review for vulnerability exposure |
| Business applications | [kql/business-applications](kql/business-applications/) | Payment beneficiary, approval-chain and payout changes |
| Splunk | [spl](spl/) | Reserved for SPL equivalents |
| Google SecOps | [yaral](yaral/) | Reserved for YARA-L equivalents |

## Query registry

| ID | Query | Data source | Maturity |
|---|---|---|---|
| GCI-KQL-WIN-001 | [Browser extension / remote-debugging flags](kql/windows/browser_extension_flags.kql) | DeviceProcessEvents | Draft |
| GCI-KQL-WIN-002 | [Suspicious PowerShell command lines](kql/windows/powershell_suspicious_commands.kql) | DeviceProcessEvents | Draft |
| GCI-KQL-ID-001 | [Entra privileged and application activity](kql/identity/entra_privileged_activity.kql) | AuditLogs | Draft |
| GCI-KQL-LNX-001 | [SSH authentication failures](kql/linux/ssh_auth_failures.kql) | Syslog | Draft |
| GCI-KQL-FW-001 | [Rare firewall destinations](kql/firewall/rare_destinations.kql) | CommonSecurityLog | Draft |
| GCI-KQL-CLD-001 | [Kubernetes Secret reads and pod creation](kql/cloud/kubernetes_secret_access.kql) | KubernetesAudit (custom) | Draft |
| GCI-KQL-VIRT-001 | [vCenter management-plane activity](kql/virtualization/vcenter_syslog_hunt.kql) | Syslog | Draft |
| GCI-KQL-AST-001 | [Software inventory review](kql/asset-inventory/software_inventory_review.kql) | DeviceTvmSoftwareInventory | Draft |
| GCI-KQL-BIZ-001 | [Payment workflow sensitive changes](kql/business-applications/payment_workflow_changes.kql) | PaymentAudit_CL (custom) | Draft |

## Required metadata for every query

Each query must document: unique ID, title, platform, use case, required tables and columns, prerequisites, query body, severity guidance, ATT&CK mapping (only when supportable), false-positive notes, tuning instructions, author/source report, last-reviewed date, and maturity status.

## Maturity lifecycle

1. **Draft** — generated or imported; not yet schema-checked.
2. **Schema-checked** — table and column names verified against the target data source.
3. **Syntax-validated** — parsed/validated in the target query engine.
4. **Lab-tested** — exercised against representative benign and malicious/synthetic events.
5. **Production-approved** — owner, severity, thresholds, suppression and response documented.
6. **Retired** — superseded or no longer useful; retain history and reason.

Never label a query validated merely because it looks syntactically plausible. Keep query status visible in reports and dashboards.

## Engineering standards and recommended innovations

- **Detection-as-code:** review changes through pull requests; preserve query history and changelogs.
- **Automated quality gates:** KQL syntax validation, required-metadata checks, duplicate-ID checks, secret scanning and markdown linting before merge.
- **Synthetic test fixtures:** include positive, negative and edge-case sample events; test expected matches and false positives.
- **Schema profiles:** record Sentinel table/column requirements and parser dependencies. Custom tables must be clearly marked and mapped to the user's actual schema before deployment.
- **ASIM support:** prefer ASIM parsers/normalized schemas where practical; keep native-table variants when normalization is unavailable.
- **ATT&CK coverage map:** map detections to tactics/techniques only when the query's observable behaviour supports the mapping; report coverage gaps.
- **Telemetry readiness:** each query lists required log source, collection method, retention and ingestion-health check.
- **Operational tuning:** include baseline period, thresholds, allowlists, suppression keys, entity mapping and expected alert volume.
- **Lifecycle controls:** add owner, review date, expiry/revalidation date and change reason. Review high-impact detections quarterly or when schemas change.
- **Safe response:** queries are read-only hunts/detections. No automatic blocking, account disabling or production changes without separately approved response playbooks.

## How to contribute

1. Add a new file under the matching technology folder.
2. Copy the metadata header from an existing query and assign a unique ID.
3. State whether the query is a detection, triage hunt, inventory lookup or investigation pivot.
4. Link the originating report/advisory and preserve the original publication date.
5. Validate table/field names and syntax; add synthetic test cases before promoting maturity.
6. Update this registry and submit the query with its test evidence.

## Source report

Initial report queries were consolidated from [Global Cyber Threat Radar — 22 November 2026](../reports/2026/11/22.md). That report is a historical source record, not proof that every referenced incident/CVE is accurate. Independently verify threat claims against primary advisories before relying on a query for incident response.
