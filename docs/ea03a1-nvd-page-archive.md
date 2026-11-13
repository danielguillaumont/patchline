# EA-03A1 — Offline NVD CVE API 2.0 page archival

**Scope:** A deliberately limited first integration step. This does **not** fetch from NVD, reconcile multiple pages, attest a complete query, build DuckDB/dbt models, or publish data to the frontend. The live/synthetic public demo remains unchanged.

The NIST NVD CVE API 2.0 exposes `format`, `version`, `timestamp`, `resultsPerPage`, `startIndex`, `totalResults`, and a `vulnerabilities` array. This slice validates an **individual offline JSON response page** before archiving its original bytes unchanged.

## Offline invocation

```powershell
uv run --locked python -m patchline.ingest.nvd --file C:\path\to\nvd-page.json --data-dir data
```

For actual source data, only import a page obtained from the official NVD CVE API 2.0 endpoint, and keep its acquisition context separately. The repository also includes the clearly fabricated `tests/fixtures/nvd-synthetic-page.json` for entirely offline smoke testing. Importing a page does not independently confirm its origin or the filters of the request that produced it. `query_parameters_verified` remains `false` accordingly.

## Validation and provenance

- Reject wrong API format/version, non-object JSON, malformed timestamps, impossible pagination, malformed identifiers, duplicate CVEs, empty pages, and invalid required status/description structures.
- Preserve optional NVD fields such as CVSS `metrics`, weaknesses, configurations, references, and unknown future fields verbatim rather than inferring missing values.
- Enforce a 20 MiB input ceiling and 2,000-CVE page limit. An empty response is not published as a healthy snapshot in this initial slice.
- Archive original page bytes to ignored `data/raw/nvd/<SHA-256>/page.json` with a completion `manifest.json` containing byte count, digest, retrieval time, response timestamp, source endpoint, pagination metadata, and observed status counts.
- Reimporting identical bytes verifies prior artifacts and preserves the original retrieval timestamp; mismatches fail instead of overwriting. Interruption may leave unmarked intermediate files that can only be completed with identical bytes.

## Next work, not claimed here

EA-03A2 will add explicit, rate-limited acquisition of scoped NVD queries with documented request parameters, paginated retrieval, page-set completeness checks, and immutable query-level manifests. EA-03B then establishes normalized NVD CVE models, joins, and regression checks in DuckDB/dbt. NVD record publication dates are not equivalent to exploit onset dates, and missing CVSS or enrichment data must not be silently treated as zero severity.

Official documentation: https://nvd.nist.gov/developers/vulnerabilities and https://nvd.nist.gov/vuln/data-feeds
