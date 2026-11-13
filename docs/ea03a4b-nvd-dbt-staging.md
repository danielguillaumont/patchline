# EA-03A4B — Isolated NVD dbt staging and data-quality contracts

**Scope:** one bounded archived NVD query, verified by EA-03A4A. A query is not a global snapshot, a live feed, or an organizational exposure inventory.

## Architecture and separation

The original DuckDB file under `data/warehouse/nvd-queries/<query_id>.duckdb` is **immutable evidence**. dbt changes DuckDB files when it materializes models. Never set `EXPLOIT_ATLAS_NVD_DBT_PATH` to that original database.

`patchline.warehouse.nvd_dbt_workspace` first calls the original EA-03A4A verification chain, then creates a **new, byte-for-byte identical working copy** using a same-directory exclusive link publication. The link points to a separate copy, *not* to the source. The workspace database is disposable; the original file remains unchanged.

`dbt_nvd` is a separate dbt project/profile from the existing `dbt` KEV/EPSS analytics. It reads `nvd_stage.query_registry`, `.cves`, and `.cvss_metrics` from the workspace and generates three staging views. No models run in the original database; no changes to KEV/EPSS marts, exports or the GitHub Pages demo.

## Guarantees and tests

- Query registry and staged rows reconcile one-to-one for CVEs and metric entries.
- Missing CVSS entries are explicitly absent; nullable scores stay `NULL`, never `0`.
- Every metric retains version, source, type, vector, severity and raw JSON. No preferred or consolidated CVSS severity is selected.
- CVE ordering, page SHA-256, page-relative positioning and original timestamps remain available.
- Four scope flags must remain `false`: point-in-time consistency, global coverage, independent source-origin verification and asset exposure.
- Invalid CVSS scores, duplicate compound metric identities, orphaned metrics, and inconsistent registry counts fail dbt tests.
- Tests run offline against synthetic sample responses. They do not make live NVD requests or prove global NVD completeness.

## PowerShell 5.1 reproduction

Run Python and lint checks:

```powershell
uv run --locked pytest tests/test_nvd_dbt_workspace.py
uv run --locked pytest
uv run --locked ruff check .
```

For a previously archived and normalized query, replace `<query_id>` with its 64-character lowercase digest. Use a **new** destination path for each dbt run:

```powershell
$queryId = '<query_id>'
$destination = Join-Path $env:TEMP ("exploit-atlas-nvd-dbt-" + [guid]::NewGuid().ToString('N') + '.duckdb')
uv run --locked python -m patchline.warehouse.nvd_dbt_workspace --data-dir data --query-id $queryId --destination $destination
$env:EXPLOIT_ATLAS_NVD_DBT_PATH = $destination
$dbtArtifacts = Join-Path $env:TEMP ("ea03a4b-target-" + [guid]::NewGuid().ToString('N'))
$dbtLogs = Join-Path $env:TEMP ("ea03a4b-logs-" + [guid]::NewGuid().ToString('N'))
uv run --locked dbt run --project-dir dbt_nvd --profiles-dir dbt_nvd --target-path $dbtArtifacts --log-path $dbtLogs
uv run --locked dbt test --project-dir dbt_nvd --profiles-dir dbt_nvd --target-path $dbtArtifacts --log-path $dbtLogs
Remove-Item Env:\EXPLOIT_ATLAS_NVD_DBT_PATH
```

When finished, the disposable workspace may be discarded. It must not be committed to Git.

## Explicitly deferred

Joining NVD to KEV/EPSS requires source-date semantics, CVE identity/coverage reconciliation and anti-look-ahead checks; that is a later checkpoint. No CVE-level public export, new UI or claimed risk score in this slice.
