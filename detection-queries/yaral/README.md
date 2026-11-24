# Google SecOps YARA-L library

Initial YARA-L 2.0 rules cover process execution and repeated authentication failures. They are intentionally marked Draft because parser and UDM field mappings differ by log source.

## Queries

| ID | Rule | UDM event type | Maturity |
|---|---|---|---|
| GCI-YARAL-WIN-001 | [Encoded / obfuscated PowerShell](windows/encoded_powershell.yaral) | PROCESS_LAUNCH | Draft |
| GCI-YARAL-ID-001 | [Repeated failed logins](identity/repeated_failed_logins.yaral) | USER_LOGIN | Draft |

## Deployment requirements

- Confirm YARA-L version and compile in the target Google SecOps rule editor.
- Confirm each parser emits the documented UDM event type and fields. In particular, verify the event semantics of security_result.action = BLOCK for failed logins.
- Tune event windows, grouping keys and thresholds to the identity population and log source.
- Rules are not enabled in a tenant and have not been tested against representative positive/negative events.
- Do not infer production detection coverage from the presence of a rule or an ATT&CK tag.

## Maturity

All entries remain Draft until parser/UDM validation, rule compilation, positive/negative lab testing, tuning, owner approval and production change control are complete.
