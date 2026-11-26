# Intelligence quality and evidence policy

This project is an analyst-support dashboard. Feed collection and automated extraction are not equivalent to independent factual verification.

## Vulnerability and CVE records

## Plain-English technology context

- Add a concise **What is it?** and **What does it do?** explanation to each threat/advisory item and KEV record, and a company/product background to relevant business intelligence.
- Use verified product/vendor fields and a curated glossary backed by primary product documentation.
- Keep advisory identifiers (such as Ubuntu USN numbers) distinct from the actual affected package/library.
- Unknown product role must remain explicitly unknown; never guess based on a product name or headline.
- Validate the context object and dashboard rendering for threat, business and KEV records. Apply it to the entire KEV catalogue, not only the seven-day additions.
- Keep the explanation short and consistent; it must not replace the original source details, affected versions, remediation or evidence links.


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

 
## Exploitation-likelihood enrichment (EPSS)

The collector performs bounded FIRST EPSS API lookups for CVEs in the latest seven-day CISA KEV additions (up to 40 records) and current advisory/research items. Requests are batched within the provider's documented URL-length limit; this is not a bulk synchronization of the full CVE population.

Each returned score is stored with its CVE, probability (0–1), percentile (0–1), provider score date, provider name and source URL. The snapshot also records retrieval time, requested/matched counts, batch count and provider errors. A missing score is not converted to zero: records distinguish no score returned, lookup failure, partial availability and no-CVE applicability.

EPSS estimates the probability that a CVE will be exploited in the next 30 days. It is not evidence that exploitation has occurred, does not measure impact, and is not an organisation-specific risk score. CISA KEV membership remains a separate known-exploitation catalogue signal. CVSS, asset applicability, exposure, criticality, compensating controls and patch state remain separate evidence dimensions and are not inferred from EPSS.

Provider: [FIRST EPSS API](https://api.first.org/epss) · [EPSS methodology and interpretation](https://www.first.org/epss/).


## CVSS technical-severity enrichment

The collector queries the NVD CVE API for up to 15 recent CISA KEV additions per daily run, with a 12-second request timeout and two attempts per CVE. It selects the highest available metric version in this order: CVSS 4.0, 3.1, 3.0, then 2.0, preferring NVD Primary metrics when available. Each metric retains version, base score, severity, vector, source/type, NVD record modification time and a direct NVD record URL.

The collector observes NVD's unauthenticated request pacing (6.1 seconds between requests); if an optional `NVD_API_KEY` environment variable is configured, it uses the higher-rate authenticated pacing. It never logs the key. Missing metrics, invalid metrics, missing CVEs and provider failures remain distinct; no zero score is fabricated.

CVSS is technical severity, not exploitation probability, proof of exploitation, or an organisation-specific risk score. EPSS remains a separate 30-day exploitation-likelihood signal, and CISA KEV remains a separate known-exploitation catalogue signal. Asset applicability, exposure, business criticality, compensating controls and patch state remain local/contextual evidence.

Provider: [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities).

 
## Remediation evidence states

Each enriched threat record carries a dated `remediation_evidence` object. States distinguish vendor guidance extracted but unverified, source-reported no-fix statements, portal-gated workarounds, specific actions extracted but unverified, no fix found in reviewed source text, and source pages not fully reviewed. Automated extraction never sets `analyst_verified` or a fixed version. A verified fixed release or mitigation requires explicit analyst verification; absence of extracted guidance is not evidence that no vendor fix exists. Evidence URLs and the UTC check timestamp are retained.


## Threat actor and campaign evidence policy

- Actor and campaign records live in `intel/phase2-intelligence.json`; the JSON Schema is `intel/schemas/phase2-intelligence.schema.json`.
- Every profile and relationship must reference one or more source IDs. Attribution confidence is explicit and includes a rationale.
- `confirmed`, `attributed`, `suspected` and `unknown` attribution states are distinct. A source's wording is preserved; a dashboard confidence label is not a claim of independent verification.
- A source page's last-modified date is not an actor or campaign last-observed date. Use null / “not stated” when the operational timestamp is unavailable.
- Campaigns are not merged based on shared tools or techniques alone. A relationship is created only when the cited source explicitly supports it.
- Empty CVE and IOC arrays are valid and do not imply that no CVEs or IOCs exist outside the reviewed source.
- Campaign detection opportunities are labelled as analyst hunt suggestions unless a detection rule is explicitly linked and independently validated. ATT&CK mapping alone is not detection coverage.
- The initial APT29 / Operation Ghost entry is sourced to the MITRE ATT&CK G0016 profile. It is a limited seed dataset, not a comprehensive actor/campaign catalogue.
- Run `python scripts/validate_phase2_intelligence.py` to validate structural integrity, source references and relationship endpoints. This does not establish the truth of the source claims.
