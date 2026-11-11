# P3.2A — dbt / DuckDB staging foundation

**Status:** Source definitions and staging models only. No KEV–EPSS join, metric mart, exported findings, or frontend yet.

The model source is the P3.1 DuckDB warehouse built from a **selected immutable snapshot pair**. This is not an automatically refreshing database. Snapshot manifests and source dates remain authoritative; do not describe the newest model as today's score without checking its score date.

## First-time setup (Windows PowerShell 5.1, project root)

1. Install the adapter: `uv add --group dev "dbt-duckdb>=1.9,<2"` then `uv sync --locked`.
2. Point the profile to the **already existing** local warehouse, using an absolute path:

   `$env:PATCHLINE_DUCKDB_PATH = (Resolve-Path "data\warehouse\patchline.duckdb").Path`

3. Validate: `uv run --locked dbt debug --project-dir dbt --profiles-dir dbt`.
4. Parse: `uv run --locked dbt parse --project-dir dbt --profiles-dir dbt`.
5. Run: `uv run --locked dbt run --project-dir dbt --profiles-dir dbt`.
6. Test: `uv run --locked dbt test --project-dir dbt --profiles-dir dbt`.

Stop if any step fails. **Never** run `dbt seed`, `dbt snapshot`, or `dbt run --full-refresh` against source data. No profile credentials, archives, generated DB files, `dbt/target`, or `dbt/logs` belong in Git.

## Isolation and grain

Raw sources live in DuckDB's `main` schema. dbt's connection target schema is `analytics` and models use dbt's default custom-schema concatenation, landing in `analytics_staging`; they are **views**. dbt should not modify `main` tables. Check `information_schema.tables` after running.

- `stg_kev`: one selected KEV snapshot/CVE, preserving `date_added`, `due_date`, source labels, release date and retrieval time.
- `stg_epss`: one selected EPSS snapshot/CVE, preserving score date, model version, complete population and retrieval time.
- Source and staging tests check uniqueness, non-null keys, numeric ranges, snapshot lineage and source-manifest row-count reconciliation.

## Limits and next milestone

The P3.2A project references only locally available validated snapshots. CI can check Python offline, but cannot build staging models without a synthetic DuckDB fixture. P3.2B will add a deterministic fixture-backed dbt CI job and an explicitly dated KEV–EPSS join while preserving the entire EPSS population. A successful dbt run or test does **not** independently prove upstream vulnerability data is fresh.
