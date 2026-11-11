# P3.4A — Validated analytical export contract

Run **after** the selected snapshot warehouse has been built and `dbt run` / `dbt test` have passed. No network access is required for export.

```powershell
$env:PATCHLINE_DUCKDB_PATH = (Resolve-Path "data/warehouse/patchline.duckdb").Path
uv run --locked dbt run --project-dir dbt --profiles-dir dbt
uv run --locked dbt test --project-dir dbt --profiles-dir dbt
uv run --locked python -m patchline.exports.analytics create --database "$env:PATCHLINE_DUCKDB_PATH" --output "data/exports/report-001"
uv run --locked python -m patchline.exports.analytics verify --output "data/exports/report-001"
```

Create `data/exports` yourself before exporting. Exports refuse to overwrite any existing destination, and source DuckDB connections are read-only. Files are published together after validation. Do not publish the synthetic fixture as real evidence.

The export bundle contains **nine dataset files**: CSV, JSON and compressed Parquet for M03 EPSS coverage of KEV, M04 population summary, and M04 five score bands. There is one `manifest.json` with schema ID `patchline.analytics-export.v1`, source snapshot IDs, retrieval/source dates, synthetic/archive classification, row counts, ordered columns, SHA-256 digests, and reconciliation totals. Every exported row comes from a pinned selected snapshot pair, not a claim of current conditions. JSON numeric fields retain probability units (0 to 1), while band and coverage shares are percentages (0 to 100). Missing percentages in empty populations remain null.

Use the **Parquet** dataset for typed analytical import (DuckDB, Python and Power BI); CSV is widely supported but may require explicit date/type interpretation. JSON is intended for static frontend data contracts. These are complete small **aggregate marts**, not bulk exports of every scored CVE. Power BI may use CSV/Parquet; the frontend should not imply synthetic demo data reflects today's real vulnerabilities.

Before writing, export verifies KEV/EPSS snapshot pairing, source date fields, exact KEV numerator/denominator reconciliation, M04 complete EPSS population and mutually exclusive score bands, empty-population nulls, and percentage calculations. The verifier checks manifest paths, exact artifact set, lengths, hashes and JSON row contracts. The manifest is a provenance record, not a digital signature; SHA-256 integrity does not establish external authenticity.

**Scope limit:** P3.4A provides stable file and provenance contracts, not a served API, live data refresh, or scheduled publishing. Never commit `data/` export bundles; they are locally generated. For public demo, label fixtures visibly as synthetic and sanitize output deliberately.
