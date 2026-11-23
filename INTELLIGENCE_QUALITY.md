# Intelligence quality and evidence policy

This project is an analyst-support dashboard. Feed collection and automated extraction are not equivalent to independent factual verification.

## Vulnerability and CVE records

- CVE IDs are extracted from titles, feed summaries, retrieved article text, and linked vendor-remediation evidence. CVE identifiers have variable numeric lengths.
- The dashboard keeps the original source URL and distinguishes feed-only content from article-enriched content.
- For CVE-bearing items, the collector follows a small number of security/advisory links explicitly present in the source article. For CISA KEV additions in the latest seven-day window, it also checks external vendor URLs supplied in the KEV notes.
- A fix is shown as source-backed only when the retrieved source contains an actionable instruction plus concrete version, build, KB, command, configuration, port, or other technical detail.
- Linked-vendor guidance is shown with its source URL and an analyst-review label. It is not an assertion that the version applies to every affected branch or that an asset is patched.
- If no concrete fix is extracted, the dashboard says that no specific fix was identified in the retrieved text or that fix status is unknown. This is not proof that no vendor fix exists.
- CISA KEV `requiredAction` is not treated as a vendor patch unless it contains concrete technical detail. KEV deployment state is never inferred from catalogue membership.

## Business intelligence

- Deal status is evidence-based: Rumoured, Announced, Signed, Completed, or Terminated. Reports of talks or possible transactions remain Rumoured; a definitive agreement is Signed; closing is Completed.
- Similar M&A coverage for the same recognized company pair and deal stage is grouped into one development with related publisher/source links.
- Law-enforcement operations and cyber incidents have dedicated categories instead of being classified as product launches.
- Headline-only or snippet-only records are explicitly marked limited. The dashboard does not invent deal terms, incident impact, or business implications when full article text is unavailable.

## Detection engineering maturity

The KQL quality workflow checks metadata, unique IDs, required-field declarations, balanced delimiters, quoted strings, and basic pipeline structure. It is a structural lint only—not the official Microsoft Kusto parser, tenant schema validation, or behavioural testing.

Query maturity must remain honest:
- Draft: not validated in the target tenant.
- Schema-checked: table and field assumptions checked against the target tenant.
- Syntax-validated: parsed by an appropriate Kusto parser or Sentinel editor.
- Lab-tested: positive and negative test events executed and reviewed.
- Production-approved: reviewed, tuned, owned, and approved for deployment.

No query should be promoted based only on static repository checks.

## Quality gates and limitations

Pull requests run dashboard/collector tests and detection-query structural checks. Daily collection validates the newly generated snapshot before committing and deploying it. A successful workflow proves that the pipeline and its checks completed; it does not prove that every global source, claim, vulnerability, vendor fix, IOC, or detection is complete and correct.

External sources can be unavailable, rate-limited, paywalled, or incomplete. The dashboard records feed health and preserves uncertainty rather than silently inventing missing information.
