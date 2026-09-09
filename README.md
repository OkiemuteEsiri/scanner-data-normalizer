# Scanner Data Normalizer

A defensive vulnerability-management data engineering project that normalizes heterogeneous scanner exports into a common schema for triage, prioritization, SLA analysis, and downstream reporting.

## Problem statement
Security programs often ingest findings from multiple scanners whose field names, severity scales, asset identifiers, timestamps, and plugin metadata differ. That inconsistency creates duplicate work, unreliable metrics, and brittle reporting pipelines.

This project demonstrates a reusable normalization layer that accepts synthetic Tenable-, Qualys-, and Defender-style records and produces a consistent canonical finding model.

## Architecture

```text
Synthetic scanner exports
        |
        v
  adapters/*
        |
        v
 canonical schema
        |
        v
 validation + fingerprints
        |
        v
 normalized JSONL / reports
```

## Features
- Scanner-specific adapters with explicit field mapping
- Canonical vulnerability finding schema
- Severity normalization to `critical/high/medium/low/info`
- UTC timestamp normalization
- Stable asset and finding fingerprints for downstream deduplication
- Validation of required fields and CVE syntax
- CLI for batch normalization
- Synthetic fixtures only; no employer/client data
- Unit tests for adapters, validation, and deterministic fingerprints
- CI workflow for tests and syntax checks

## Usage

```bash
python -m src.scanner_normalizer.cli --scanner tenable --input data/tenable_findings.json --output normalized.jsonl
python -m unittest discover -s tests -v
```

## Design decisions
- **Loss-aware normalization:** source-specific metadata is preserved in `source_metadata`.
- **Deterministic identity:** hashes use normalized stable fields for repeatable reconciliation.
- **Strict validation:** malformed records fail clearly rather than contaminating reporting pipelines.
- **No live scanning:** the project processes static synthetic exports and performs no network targeting.

## Limitations
Adapters model representative synthetic schemas rather than every vendor version. Fingerprints assist reconciliation but do not replace a mature CMDB identity strategy. Live threat enrichment and exploit execution are intentionally out of scope.

## Skills demonstrated
Python data engineering, vulnerability management, schema design, data quality controls, deterministic reconciliation, testing, CI/CD, defensive security automation, and technical documentation.

## Roadmap
CSV ingestion/export, schema versioning, richer asset identity resolution, pluggable KEV/EPSS enrichment, and duplicate/completeness metrics.
