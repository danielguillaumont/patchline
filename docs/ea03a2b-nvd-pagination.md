# EA-03A2B — Bounded NVD query pagination

This checkpoint adds a **separate** NVD query-level acquisition path, building on EA-03A1's validated single-page archive and EA-03A2A's explicitly allowed HTTPS request transport.

## Contract and scope

`patchline.nvd-query-pagination.v1` is written only after every required page has been fetched, structurally validated, deduplicated, and reconciled to NVD's consistent `totalResults` report during the query. Each page records its `startIndex`, response timestamp, requested URL without secrets, record count, content digest, and raw immutable archive path. The query record is content-addressed and reuses identical archived bytes while retaining the first successful acquisition timestamp.

`pagination_reconciled=true` proves **only** that the distinct CVE IDs returned during this bounded retrieval equal the NVD-reported query total and that there are no offset gaps or cross-page duplicates. It **does not** establish that the NVD database was frozen across multiple HTTP calls. NVD can change between calls, even when `totalResults` remains constant. Accordingly, `point_in_time_consistency_verified=false` and `global_nvd_completeness_attested=false` always remain explicit.

## Usage

All network traffic is opt-in. Windows PowerShell 5.1 example:

```powershell
uv run --locked python -m patchline.ingest.nvd_pagination `
  --last-mod-start 2026-11-12T00:00:00Z `
  --last-mod-end 2026-11-13T00:00:00Z `
  --results-per-page 100 `
  --max-pages 10 `
  --data-dir data `
  --allow-network
```

Single-CVE mode (with the same safety gates):

```powershell
uv run --locked python -m patchline.ingest.nvd_pagination `
  --cve-id CVE-2026-12345 --results-per-page 1 `
  --max-pages 1 --data-dir data --allow-network
```

The examples above are commands, not assertions of the current existence of any CVE or response. Optional `NVD_API_KEY` may be set in the environment; never commit it. Keys are sent in headers and not saved in manifests or request URLs.

## Failure behavior and resource bounds

- Allowlisted NVD CVE API 2.0 endpoint and query modes only. The initial request is reconstructed from approved parameters; subsequent URLs vary **only** in `startIndex`.
- Serialized HTTPS, redirects rejected, finite retries, and conservative spacing between successful pages, with separate retry spacing. Concurrent polling is not implemented.
- Caller chooses a maximum page budget (default 10; hard ceiling 20), with 1–2,000 records requested per page. Aggregate raw page bytes may not exceed 64 MiB. Exceeding either limit fails without publishing a query-completion marker.
- A changed `totalResults`, mismatch between requested and returned offsets, incomplete intermediate page, duplicate CVE across pages, malformed response, or exhausted retry budget stops the run.
- All remote responses are validated **before** raw page archival. If archive writing later fails, previously archived immutable pages may remain, but no new query-completion marker is published. Identical retries can reuse them.
- Existing EA-03A1 validation rejects **zero-result** API responses; this milestone deliberately fails closed for those rather than inventing an empty query contract. Handling zero-result queries needs a separate reviewed contract change.
- A coherent NVD API response sequence is not necessarily a reproducible point-in-time snapshot. There is no DuckDB/dbt integration, trusted scheduled executor, CVE-level export, or change to the synthetic public demo in this slice.

## Offline verification

```powershell
uv run --locked pytest tests/test_nvd_pagination.py
uv run --locked ruff check .
uv run --locked pytest
```

All new tests use local fake transports; no NVD network activity occurs. Next checkpoint: interpret and normalize NVD CVE records into stable typed models with explicit CVSS version, status and incomplete-field handling before creating a new analytical join.

NVD API reference: https://nvd.nist.gov/developers/vulnerabilities
