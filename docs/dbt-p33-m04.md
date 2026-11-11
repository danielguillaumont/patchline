# P3.3C — M04 complete EPSS score distribution

Status: dbt implementation; only claim verified numbers after the local and GitHub CI checks pass.

## Scope and population

M04 uses **all** records in `analytics_staging.stg_epss` from the selected archived FIRST EPSS score date (not the KEV-only subset). The mart contains two independently useful views in `analytics_marts`:

- `m04_epss_population_summary`: exactly one row for the selected EPSS snapshot, with `scored_cve_count`, minimum, maximum, arithmetic mean, and continuous P25/P50/P75/P90 quantiles of the **EPSS score**. Do not confuse these quantiles with FIRST's `percentile` field.
- `m04_epss_score_bands`: five exhaustive, non-overlapping probability bands, with stable `band_order`, absolute `cve_count`, full-population denominator, and share in percent. The final band includes the exact value 1.0.

| Order | Probability range | Upper inclusive? |
|---|---|---|
| 1 | 0.000 ≤ EPSS < 0.001 | No |
| 2 | 0.001 ≤ EPSS < 0.010 | No |
| 3 | 0.010 ≤ EPSS < 0.100 | No |
| 4 | 0.100 ≤ EPSS < 0.500 | No |
| 5 | 0.500 ≤ EPSS ≤ 1.000 | Yes |

These bins are an **analytical presentation choice**, not a vulnerability severity scale, remediation priority, or validated risk classification. EPSS probabilities represent model estimates rather than confirmed exploitation observations. Snapshot ID, source date, UTC retrieval time, and model version are carried on every row.

The selected snapshot is the warehouse's pinned EPSS source, not automatically the latest feed on the Internet. SQL models do not download or refresh input data. The pipeline requires the P3.1 source validations to have passed.

## Null and empty-population policy

Input score values are required by the archived warehouse contract. Exact `0.0` scores must remain valid scored rows, not NULLs or missing observations. `scored_cve_count` is 0 if the selected scored population is empty; quantiles and other summary score statistics are NULL in that case. Five band rows still exist, with zero counts, and their `population_percent` is NULL (undefined denominator). No imputation or removal of low-probability CVEs.

## Deterministic synthetic CI fixture

The existing fixture contains four EPSS scores: `[0.0, 0.01, 0.8, 1.0]`. Expected counts in the five bands are `[1, 0, 1, 0, 2]`. Score quantiles (continuous interpolation) are P25 `0.0075`, median `0.405`, P75 `0.85`, P90 `0.94`; average `0.4525`. Percentages remain unrounded in dbt; round only in presentations.

CI builds all dbt models, runs all dbt data tests and invokes `verify-m04` to assert the exact fixture band counts, full-population denominator, provenance, zero/one boundary handling and expected quantiles. The fixture is fully synthetic and resides in a temporary ignored DuckDB database. No live feed or generated database belongs in Git.

## Local validation

From the repository root on Windows PowerShell 5.1:

```powershell
$env:PATCHLINE_DUCKDB_PATH = Join-Path $env:TEMP 'patchline-m04-validation.duckdb'
uv run --locked python -m patchline.fixtures.ci_warehouse create --output $env:PATCHLINE_DUCKDB_PATH
uv run --locked dbt run --project-dir dbt --profiles-dir dbt
uv run --locked dbt test --project-dir dbt --profiles-dir dbt
uv run --locked python -m patchline.fixtures.ci_warehouse verify-m04 --output $env:PATCHLINE_DUCKDB_PATH
```

Choose a new output filename if that temporary file exists; fixture creation deliberately refuses to overwrite an existing database.
