# Architecture

## Objective
Create a vendor-neutral vulnerability finding representation that downstream risk, SLA, trend, and reporting systems can consume without embedding scanner-specific assumptions.

## Processing stages
1. **Ingestion** — read a static export from an explicitly selected adapter.
2. **Mapping** — translate source fields to the canonical finding contract.
3. **Validation** — reject unsupported severities, malformed CVEs, invalid IP addresses, and missing identity fields.
4. **Normalization** — convert severity labels, timestamps, CVEs, status, and scanner names to stable forms.
5. **Identity** — compute deterministic asset and finding fingerprints from normalized fields.
6. **Preservation** — retain useful vendor-specific attributes in `source_metadata`.
7. **Output** — emit one canonical JSON object per line for downstream processing.

## Canonical identity strategy
`asset_fingerprint = SHA256(asset_id | hostname | ip)[:24]`

`finding_fingerprint = SHA256(asset_fingerprint | vulnerability_id | normalized_cves)[:24]`

The fingerprint design is intentionally transparent and deterministic. It enables synthetic demonstrations of reconciliation while acknowledging that production identity resolution normally requires CMDB, cloud-resource, agent, and network context.

## Trust boundaries
Input is treated as untrusted data even though included fixtures are synthetic. Normalization functions validate structured fields before constructing immutable `Finding` objects. The project never initiates scanning or connects to target systems.

## Failure model
The engine fails closed on malformed mandatory fields instead of silently coercing them. This is important for vulnerability-management reporting because silently accepted bad records can distort asset counts, SLA metrics, ownership, and exposure trends.

## Extension model
A new scanner integration implements a mapping function returning `Finding` through `build_finding`. Shared validation and fingerprinting remain centralized, limiting schema drift across adapters.
