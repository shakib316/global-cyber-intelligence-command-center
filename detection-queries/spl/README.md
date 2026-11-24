# Splunk SPL library

Draft SPL hunts are provided as equivalents to selected Sentinel/Google SecOps behaviours where the telemetry model is explicit.

## Queries

| ID | Query | Data source | Maturity |
|---|---|---|---|
| GCI-SPL-WIN-001 | [Encoded / obfuscated PowerShell](windows/suspicious_powershell_execution.spl) | Sysmon Event ID 1 | Draft |
| GCI-SPL-WIN-002 | [Registry Run / RunOnce persistence](windows/registry_run_key_persistence.spl) | Sysmon Event ID 13 | Draft |
| GCI-SPL-NET-001 | [Rare network destinations](network/rare_destination_hunt.spl) | Network_Traffic CIM | Draft |

## Deployment requirements

- Confirm index and sourcetype names, field extractions, and event-code mappings.
- The Sysmon hunts assume Sysmon Operational XML events and the listed extracted fields.
- The network hunt assumes an accelerated Network_Traffic.All_Traffic CIM data model with src, dest and dest_port.
- CIM compliance is not inferred. Verify the data model and field lineage in the target Splunk deployment.
- These are analyst hunts, not enabled correlation searches or production alerts.
- Queries have not been run in a Splunk search head or tested against your local data.

## Maturity

All entries remain Draft until syntax validation in the target Splunk version, schema verification, positive/negative event tests, tuning, ownership and change approval are documented.
