# Example Normalization Quality Report

## Scope
Synthetic Tenable-style export included in `data/tenable_findings.json`.

## Input summary
- Records received: 2
- Records expected after normalization: 2
- Synthetic assets represented: 2
- Severity distribution: 1 high, 1 medium

## Quality controls demonstrated
- Required identity fields present
- IPv4 addresses syntactically valid
- CVE identifiers normalized to uppercase canonical form
- UTC timestamps retained in normalized form
- Scanner severity values translated to canonical labels
- Deterministic asset and finding fingerprints generated
- Source-specific plugin family retained as metadata

## Example normalized record
```json
{
  "scanner": "tenable",
  "asset_id": "asset-001",
  "hostname": "lab-app-01",
  "ip_address": "10.10.0.10",
  "vulnerability_id": "10001",
  "title": "Synthetic TLS Library Finding",
  "severity": "high",
  "cves": ["CVE-2025-1234"],
  "status": "open"
}
```

Fingerprint values are generated at runtime and intentionally omitted from this illustrative excerpt.

## Remediation and revalidation
If a record fails validation, correct the adapter/upstream mapping, add a regression fixture, rerun unit tests, normalize the batch again, and reconcile source count against canonical output count before downstream reporting.

## Interpretation
Normalization improves data consistency; it does not independently establish exploitability, business criticality, or active exploitation. Those factors belong in subsequent enrichment and prioritization stages.
