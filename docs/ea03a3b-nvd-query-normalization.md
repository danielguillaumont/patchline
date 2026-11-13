# EA-03A3B — Verified NVD query normalization

**Contract:** `patchline.nvd-normalized-query.v1`

EA-03A3B extends EA-03A3A from **one archived NVD page** to **one completed, bounded NVD query**. It is strictly offline: no API calls, scheduler, DuckDB writes, dbt models, export changes or React changes occur in this checkpoint.

## Source and behavior

Input: `data/raw/nvd-queries/<query_id>/manifest.json` created by EA-03A2B, with the linked immutable page archives under `data/raw/nvd/<page_sha256>/`.

- Verify the SHA-256 content-addressed query ID against the approved request and the ordered page hash list.
- Rebuild the allowlisted request and verify reported counts, page offsets, request URLs, byte budgets and pagination-reconciliation flags.
- Rehash every linked raw NVD page and validate each page's original immutable archive manifest against the page contents.
- Apply the EA-03A3A normalization contract to each page. Preserve source timestamps and CVSS v2, v3.0, v3.1, v4.0 metric entries without selecting a fabricated preferred score.
- Detect duplicate CVE IDs across pages and **reject** the whole query. No last-write-wins or inferred conflict resolution.
- Include the source page hash, page start index and within-page position on every normalized CVE record.
- Require the final ordered record count to agree with the query's **reported** total, then write an immutable, idempotent output at `data/normalized/nvd-queries/<query_id>/normalized.json`.
- Refuse to replace an existing output with mismatched bytes. No new query-level normalized file is written if verification fails.

## Reproduction (PowerShell 5.1)

Run focused tests first, followed by Ruff and the full Python suite:

```powershell
uv run --locked pytest tests/test_nvd_query_normalize.py
uv run --locked ruff check .
uv run --locked pytest
```

A completed EA-03A2B query can then be normalized **without network access**:

```powershell
uv run --locked python -m patchline.ingest.nvd_query_normalize `
  --data-dir data `
  --query-id <LOWERCASE_SHA256_FROM_NVD_QUERY>
```

The output is a local normalized projection, not a public dataset. Running the command again verifies the existing bytes instead of replacing them. The tests use synthetic NVD response pages and an injected fake transport; they do **not** contact NVD.

## Important limitations

- Pagination reconciles NVD's **reported** total during one bounded retrieval. It is **not** an atomic point-in-time copy of NVD, nor proof of global corpus completeness or verified upstream origin.
- Duplicate and conflicting CVE records in a query are explicitly rejected rather than arbitrarily resolved. Reconciliation **between distinct acquisitions or historical versions** has not been implemented.
- NVD CVSS values describe severity characteristics; KEV and EPSS remain distinct evidence and probability signals.
- CPE configuration trees are retained, not evaluated into a statement about a customer's installed software or exposure.
- No warehouse staging tables, tested dbt joins, versioned CVE-level exports, or publicly searchable NVD records are claimed yet.

## Next checkpoint

EA-03A4 should build strictly versioned **DuckDB staging** for this source-pinned normalized query, then **dbt tests/transformations** with missingness, CVSS-version semantics and source lineage. Do not connect NVD to public synthetic pages until the analytical export and disclosure boundary is reviewed separately.

Reference: https://nvd.nist.gov/developers/vulnerabilities
