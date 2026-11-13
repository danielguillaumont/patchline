# EA-03A2A — Bounded NVD API acquisition

**Scope:** Explicit HTTPS acquisition of **one** NVD CVE API 2.0 response page. This adds real network access behind a deliberate `--allow-network` switch. It does **not** perform pagination, guarantee complete query results, synchronize the corpus, update DuckDB/dbt, or publish data to the React frontend.

It builds directly on EA-03A1: raw bytes are validated by `validate_nvd_page` and archived through `archive_nvd_page`, preserving the existing single-page validation boundary. A separate immutable request record documents which *actual* official HTTPS query was made. Neither record is a cryptographic proof of NIST authorship independent of the HTTPS transport.

## First use

From the repository root in Windows PowerShell 5.1:

```powershell
# Optional: only in your private terminal session; never commit an API key.
# $env:NVD_API_KEY = "your-key"

uv run --locked python -m patchline.ingest.nvd_acquire `
  --cve-id CVE-2024-3094 `
  --results-per-page 1 `
  --data-dir data `
  --allow-network
```

Or for an explicit UTC last-modified window (up to 120 days) on the first page:

```powershell
uv run --locked python -m patchline.ingest.nvd_acquire `
  --last-mod-start 2026-11-01T00:00:00Z `
  --last-mod-end 2026-11-02T00:00:00Z `
  --results-per-page 100 `
  --data-dir data `
  --allow-network
```

A `--cve-id` lookup may return no records and then **fails closed** under the existing EA-03A1 rule. Missing end dates, naive timestamps, ranges over 120 days, a wrong API response page, and unexpected CVE IDs are also rejected. Omitting `--allow-network` prohibits network activity. Set the optional `NVD_API_KEY` environment variable outside source control; the key is sent only in the request header, never stored in the request URL, manifest, or CLI result.

## Provenance and limitations

- NVD endpoint is fixed to `https://services.nvd.nist.gov/rest/json/cves/2.0` with only approved query modes: `cveId` **or** paired `lastModStartDate` and `lastModEndDate`.
- The first-page request is always `startIndex=0`, with explicit `resultsPerPage` (default 100, maximum 2,000). HTTPS redirects are rejected rather than forwarding API keys.
- Network errors and HTTP 429/5xx have a finite three-attempt budget and deliberate request pacing. Other HTTP errors fail without retry. NVD rate limits are shared across an IP/key, so other clients may still trigger throttling; this is **not** a global rate-limit coordinator.
- The response body has a 20 MiB ceiling and is subjected to the EA-03A1 structural checks. The recorded response pagination must not exceed request bounds, and `cveId` response identity must match the requested ID.
- `data/raw/nvd/<SHA-256>/page.json` retains the original response bytes, while `data/raw/nvd-acquisitions/<SHA-256>/acquisition.json` records the exact query URL and parameters, response timestamp, digest, row count, retrieval time and scope. These paths are Git-ignored local state.
- A request which reports more records than the first page returns is marked `reported_total_fits_first_page=false`. Even where it reports only one page, `completeness_attested=false` and `point_in_time_consistency_verified=false` because this slice does not prove a stable point-in-time dataset. The public synthetic demo is unchanged.
- Identical response bytes and request parameters reuse the same immutable acquisition record; changed bytes create a distinct content-addressed record. Tampering fails closed. An interruption can leave raw bytes without the request record, which the identical retry can complete.
- EA-03A1's page manifest uses `acquisition=offline_supplied_page` for accepted bytes. In this slice, the additional acquisition manifest provides the verified HTTPS request context; the original page contract is intentionally unchanged.

## Offline validation

```powershell
uv run --locked pytest tests/test_nvd_acquire.py
uv run --locked ruff check .
uv run --locked pytest
```

All new tests use injected fake transport responses and never contact NVD. The next step, EA-03A2B, is bounded multi-page retrieval with cross-page duplicate checks, stable query reconciliation, explicit abort-on-partial behavior and a versioned query-level completeness record. Only after that do NVD normalization and DuckDB/dbt models begin.

Official documentation: https://nvd.nist.gov/developers/vulnerabilities
