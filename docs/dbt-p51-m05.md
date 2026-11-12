# P5.1A: M05 KEV and EPSS cohort bands

**Status:** New dbt mart, quality tests, and deterministic fixture verification. M05 is not yet published by the v1 export contract and does not appear in Spectral Index.

## Question and methodology

Among vulnerabilities listed in the selected CISA KEV snapshot, how many have EPSS probability scores in each existing M04 band? How many KEV records have no score on the paired EPSS snapshot date?

M05 is one view, `analytics_marts.m05_kev_epss_cohort_bands`, with exactly six rows. Rows 1 to 5 reuse the five M04 ranges without changing inclusivity or score boundaries. Row 6 represents KEV CVEs with no matching scored EPSS record. It is **not** a zero-probability bucket. Actual EPSS score `0.0` belongs in band 1.

The mart exposes three distinct populations:

- `denominator_all_kev`: total KEV CVEs from the selected catalog, including unmatched ones. Every row has an all-KEV percentage, or `NULL` if the KEV catalog is empty.
- `denominator_scored_kev`: KEV CVEs with a matching EPSS row. Only bands 1 to 5 have a scored-KEV percentage; it is `NULL` if there are no scored KEV CVEs.
- `full_epss_denominator`: all CVEs scored by EPSS on the paired scoring date, including those absent from KEV. Scored bands expose M04 population counts and percentages unchanged. Row 6 has `NULL` for these EPSS fields, since unmatched KEV has no EPSS band.

This is a **descriptive comparison**, not independent control/treatment cohorts, a statistical significance test, confirmation of exploitation, organizational exposure, or a remediation priority score. The KEV scored subset is contained in the full EPSS scored population. Source snapshot IDs, source dates, retrieval timestamps, and EPSS model version follow M03.

## Deterministic synthetic fixture expectations

Selected fixture: 3 KEV CVEs, 4 scored EPSS CVEs, 2 overlaps, 1 KEV-only record. The KEV band counts for rows 1 to 6 are `[0, 0, 1, 0, 1, 1]`. M04's full-population counts remain `[1, 0, 1, 0, 2]`. Each of rows 3, 5 and 6 has 33.333...% of all KEV; rows 3 and 5 each have 50% of scored KEV. The unmatched row has no scored-KEV or full-population share.

`dbt test` must validate six categories, complete reconciliation, shared threshold definitions, the three denominators, empty-population nulls, and source lineage. `verify-m05` independently inspects the materialized view in the synthetic database. CI must still successfully create the existing nine-file M03/M04 export bundle.

## Run locally in PATCHLINE MAIN (Windows PowerShell 5.1)

Run these commands in sequence from the repository root, using a fresh temporary DuckDB filename. Never run `create` against an existing database:

```powershell
$env:PATCHLINE_DUCKDB_PATH = Join-Path $env:TEMP ("patchline-m05-" + [guid]::NewGuid().ToString("N") + ".duckdb")
uv run --locked python -m patchline.fixtures.ci_warehouse create --output $env:PATCHLINE_DUCKDB_PATH
uv run --locked dbt run --project-dir dbt --profiles-dir dbt
uv run --locked dbt test --project-dir dbt --profiles-dir dbt
uv run --locked python -m patchline.fixtures.ci_warehouse verify-m05 --output $env:PATCHLINE_DUCKDB_PATH
```

Never commit generated DuckDB databases or archived source dumps. P5.1B will design a new versioned consumer contract for M05, without silently changing `patchline.analytics-export.v1` or its nine files.
