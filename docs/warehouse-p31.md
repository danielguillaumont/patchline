# P3.1 — Source-traceable DuckDB warehouse (foundation)

This slice creates a **new** local DuckDB database from one archived KEV snapshot and one archived EPSS snapshot. It does not download data, implement dbt models, publish BI exports, or calculate the final metric dictionary.

## Build command

After `uv add "duckdb>=1.1,<2"` and `uv sync --locked`, run:

`uv run --locked python -m patchline warehouse build --data-dir data --output data/warehouse/patchline.duckdb`

If you have more than one archive for either source, provide **both** explicit snapshot identifiers using `--kev-snapshot` and `--epss-snapshot` (full 64-character lowercase SHA-256 IDs). The build refuses to infer the latest snapshot from directory order. The existing database is **never overwritten**. To rebuild, select a different output file; do not manually replace your existing validated database.

The selected archived bytes are checked against each SHA-256 manifest and revalidated through the existing source validators. Manifest row counts, model metadata, and source dates are reconciled with the payloads. The output is staged locally and published only after both DuckDB row counts match validated source counts. Failure leaves the prior warehouse untouched.

## Current tables

- `source_snapshots`: source ID, SHA-256 snapshot ID, acquisition timestamp, source date, model version, validated row count
- `raw_kev_snapshot`: one row per KEV CVE and snapshot; typed dates and source-provided optional descriptive fields
- `raw_epss_daily`: one row per scored CVE in the selected EPSS snapshot, with score date, model version, probabilities, and snapshot lineage

This is a **single snapshot pair** warehouse, not yet a historical multi-run repository. EPSS scores are stored as DuckDB `DOUBLE` for analytical computation; the immutable gzip retains the source's original decimal text. EPSS probabilities do not prove exploitation, and KEV presence does not indicate exposure in any particular organization.

No warehouse files or source archives belong in Git; `/data/*` is ignored. The automated integration test uses synthetic archives. A real local build is required before merging this feature.
