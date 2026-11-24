# Detection Query Changelog

Record every new query, material logic/schema change, maturity promotion and retirement. Link the pull request or commit where possible.

## 2026-11-22
- Created categorized KQL library and imported query examples from the 22-Nov-2026 report.
- Added baseline hunts for PowerShell, SSH authentication failures and rare firewall destinations.
- Added Draft maturity labels and schema/false-positive guidance.
- Added GitHub Actions static metadata and unique-ID quality checks. These do not parse KQL or test tenant data.

## 2026-11-24
- Added seven Draft KQL hunts from the 24-Nov-2026 radar: N-able Mail Assure SSRF egress, MONAI Label path traversal, Xen Orchestra empty-token auth bypass/IOCs, GL.iNet persistence, Wing FTP session enumeration, Idunno.AntiCsrf IIS/DLL, and payment-workflow sequence correlation.
- Updated the README query registry and added the network/infrastructure category.
- All new queries remain Draft; custom schemas and thresholds require tenant mapping, syntax validation and positive/negative test fixtures.

## Entry template
- Date:
- Query ID:
- Change: Added / Updated / Promoted / Retired
- Reason and source:
- Schema or logic changes:
- Validation evidence:
- Reviewer:
