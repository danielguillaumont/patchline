# EA-03A3A - Offline NVD normalization contract

**Format:** `patchline.nvd-normalized-page.v1`

This checkpoint implements a source-linked, deterministic projection of **one** already
validated NVD CVE API 2.0 response page. It deliberately does not merge pages, operate a
query-level snapshot, write DuckDB/dbt tables, run a scheduled executor, or publish new
consumer datasets. The existing public synthetic demo is untouched.

## What is normalized

- CVE ID, source identifier (nullable), analysis status, published and modified strings.
  NVD timestamps are preserved **as provided**, including when they omit timezone offsets.
- English description when present; all source-language descriptions retained. No translation.
- CVSS v2, v3.0, v3.1 and v4.0 **metric entries**, each with separate version, source,
  type, vector, score, severity and full original metric object. No arbitrary "best score"
  selection. Absent score remains null, absent metrics an empty list, never a fabricated 0.
- Weaknesses, references and affected-configuration trees kept as original JSON objects.
  CPE boolean operators, negation and version bounds are **not flattened or evaluated**.
- Explicit per-record missingness flags. No assertion of product installation, exposure,
  exploitation probability or organizational risk.

Unknown CVSS metric families and malformed nested fields fail rather than silently
vanishing. The input is checked using the existing EA-03A1 page validator.

## Source-pinned replay (Windows PowerShell 5.1)

The repository includes a fabricated offline fixture. Archive it first:

```powershell
uv run --locked python -m patchline.ingest.nvd `
  --file tests/fixtures/nvd-synthetic-page.json --data-dir data
```

The command returns a `snapshot_id` (lowercase SHA-256). Reuse that exact identifier:

```powershell
uv run --locked python -m patchline.ingest.nvd_normalize `
  --snapshot-id <SHA256_FROM_PREVIOUS_COMMAND> --data-dir data
```

The immutable local result is at
`data/normalized/nvd-pages/<snapshot_id>/normalized.json` (ignored by Git).
The source page bytes are rehashed and the raw-page manifest metadata is reconciled to
revalidated content *before* output. Identical replay verifies existing bytes; a mismatch
never overwrites them. The output includes SHA-256 pointers to both archived page and
archived manifest.

The original raw NVD page path is the canonical source of truth. The normalized projection
is **not** a replacement for that raw archive or a certification of upstream authenticity.
An archived page alone cannot attest to independently verified NVD origin or complete
query acquisition.

## Verification (no network)

```powershell
uv run --locked pytest tests/test_nvd_normalize.py
uv run --locked ruff check .
uv run --locked pytest
```

## Next checkpoint

EA-03A3B should verify complete query manifests, normalize and reconcile their linked page
sets, handle duplicate CVE IDs and evolving records explicitly, and only then define DuckDB
staging and dbt transformations. A reconciled query is not an atomic NVD database snapshot.

References: https://nvd.nist.gov/developers/vulnerabilities
