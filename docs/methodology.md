# Methodology and Validation Workflow

## Data-quality objectives
The normalizer is designed around five controls: completeness, syntactic validity, semantic consistency, deterministic identity, and source traceability.

## Validation workflow
1. Validate required identity fields.
2. Validate IP syntax when an address is supplied.
3. Normalize severity to the canonical five-level model.
4. Normalize CVE identifiers, remove duplicates, and reject malformed values.
5. Convert timestamps to UTC ISO-8601.
6. Generate deterministic fingerprints.
7. Preserve selected source metadata for investigation and reconciliation.
8. Compare normalized output counts to input counts.

## Remediation workflow for rejected records
- Identify the failed validation control from the exception.
- Correct the source mapping or upstream export transformation rather than weakening validation.
- Add a regression fixture representing the problematic record shape.
- Add or update a unit test.
- Re-run the normalization batch and compare input/output counts.
- Review fingerprints if the corrected field participates in identity generation.

## Validation after schema changes
Any canonical schema change should be treated as a data-contract change. Validate all adapters, confirm deterministic fingerprints remain intentional, review backward compatibility, and document migration implications before consuming the output in SLA or executive reporting.

## Security considerations
This repository uses only synthetic records. No credentials, customer identifiers, production IPs, or employer-specific scanner exports should be committed. The CLI processes local files and does not perform network discovery, exploitation, or scanner API authentication.

## ATT&CK context
Scanner normalization is primarily security engineering rather than detection logic. Downstream vulnerability records may support prioritization of exposures associated with techniques such as **T1190 Exploit Public-Facing Application** and **T1210 Exploitation of Remote Services**, but this project does not claim that a vulnerability finding proves adversary behavior.
