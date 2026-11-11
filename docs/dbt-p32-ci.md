# P3.2 CI hardening — deterministic dbt fixture

The GitHub Actions `dbt offline fixture` job independently tests dbt-duckdb against an **invented**, fixed-size warehouse matching the P3.1 three-table raw schema. It does not access CISA, FIRST, network feeds, or any local raw snapshot. It does not assert freshness or external data correctness.

## Fixture contracts

- 2 snapshot manifests, with deterministic synthetic SHA-256 identifiers; 3 KEV rows; 4 EPSS rows
- KEV/EPSS CVE overlap: exactly 2; one KEV-only CVE; two EPSS-only CVEs
- Fixed synthetic dates and model version, EPSS boundary values 0 and 1, one blank vendor product field
- `create` fails rather than overwrite an existing database; parent directory must already exist
- `verify` opens the warehouse read-only and checks expected staging **views**, count parity, manifest IDs, and overlap

These identifiers and scores are synthetic test inputs. They must never appear in portfolio metric exports or user-visible findings as real observations.

## Windows PowerShell 5.1 reproduction (from repository root)

```powershell
$ErrorActionPreference = "Stop"
$fixture = Join-Path $env:TEMP "patchline-ci-manual.duckdb"
if (Test-Path -LiteralPath $fixture) { throw "Fixture already exists; choose a new path." }
$env:PATCHLINE_DUCKDB_PATH = $fixture
uv run --locked python -m patchline.fixtures.ci_warehouse create --output "$fixture"
if ($LASTEXITCODE -ne 0) { throw "Fixture creation failed." }
uv run --locked dbt debug --project-dir dbt --profiles-dir dbt
if ($LASTEXITCODE -ne 0) { throw "dbt debug failed." }
uv run --locked dbt parse --project-dir dbt --profiles-dir dbt
if ($LASTEXITCODE -ne 0) { throw "dbt parse failed." }
uv run --locked dbt run --project-dir dbt --profiles-dir dbt
if ($LASTEXITCODE -ne 0) { throw "dbt run failed." }
uv run --locked dbt test --project-dir dbt --profiles-dir dbt
if ($LASTEXITCODE -ne 0) { throw "dbt test failed." }
uv run --locked python -m patchline.fixtures.ci_warehouse verify --output "$fixture"
if ($LASTEXITCODE -ne 0) { throw "Fixture verification failed." }
```

The fixture file is generated in a temporary directory and must not replace `data/warehouse/patchline.duckdb`. It is ignored by `*.duckdb`. Do not publish fixture database or generated dbt artifacts.

## Quality gates and limits

Python tests and Ruff remain in the original CI job. A second job tests dbt's actual staging SQL, generic source/model tests, and singular data tests against the fixture. The fixture is intentionally small; separately validate real archive row counts locally when changing ingestion or production warehouse behavior. This milestone does **not** create KEV–EPSS analytics marts. Deprecation notices from third-party Actions should be reviewed separately, using versioned and reviewed upgrades.
