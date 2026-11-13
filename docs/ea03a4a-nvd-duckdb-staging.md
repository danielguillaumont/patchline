# EA-03A4A — Verified NVD DuckDB staging

**Contract:** `patchline.nvd-duckdb-query-staging.v1`

This checkpoint loads **one** previously archived, independently checked-by-the-local-toolchain NVD query into **its own DuckDB database**. It is an offline engineering slice and does **not** change KEV/EPSS warehouse tables, dbt models, analytical exports, public Pages demo, or vulnerability explorer.

## Inputs and lineage

- Requires the archived query and every immutable raw page from EA-03A2B, plus its canonical `data/normalized/nvd-queries/<query_id>/normalized.json` from EA-03A3B.
- Rechecks archived raw page hashes, query manifest, pagination reconciliation, ordered CVE identity, and byte-for-byte equality of the normalized file to the recalculated projection **before opening a destination for write**.
- A query ID is not a global NVD snapshot: it only identifies one bounded retrieval reconciled to the API's reported count.
- Default output is `data/warehouse/nvd-queries/<query_id>.duckdb` (local and untracked). An explicit `--database` path can name another *new* file. If the file exists, it is **read-only verified**, never updated or replaced.
- Database construction is transactional in a temporary file; publishing uses a same-directory hard link with no overwrite. A failure does not replace any preexisting database. The writer requires a filesystem that supports hard links (e.g., NTFS).

## Staging schema

The isolated database contains three tables in `nvd_stage`:

- `query_registry`: the source query ID, SHA-256 hashes of the upstream manifest and normalized input, source type, row/metric/page counts, explicit false completeness/exposure flags, and staging contract version.
- `cves`: source CVE ID, position, original publication/modification strings, descriptive fields, exact page lineage, explicit missingness flags, and a lossless JSON representation of each normalized CVE record.
- `cvss_metrics`: one row **per reported metric entry**, including CVSS v2/3.0/3.1/4.0 version, metric source/type, nullable vector/score/severity, and original version-specific metric object. There is **no invented preferred severity score**, zero imputation, or CPE-to-asset inference.

The loader checks row-by-row database contents, schema inventory, and source hashes on replay. It does not reconcile duplicate identities **across different NVD queries**, update already loaded snapshots, or assert upstream origin independent of the archived payload.

## PowerShell 5.1 reproduction

From the repository root, once a completed normalized query ID exists:

```powershell
uv run --locked pytest tests/test_nvd_duckdb_stage.py
uv run --locked ruff check .
uv run --locked pytest

uv run --locked python -m patchline.warehouse.nvd_stage `
  --data-dir data `
  --query-id <THE_64_CHAR_QUERY_ID>
```

Re-running the last command verifies identical staging content and returns `verified_existing`, without rewriting the database. You may inspect it with DuckDB using a read-only connection. All automated tests use invented, offline NVD response pages. No network requests occur during the staging command.

## Next checkpoint

EA-03A4B: versioned dbt staging models, strict sources and tests, missingness/CVSS semantics, lineage and justified KEV/EPSS joins. This stage remains deliberately separate from any public CVE-level export or live service.
