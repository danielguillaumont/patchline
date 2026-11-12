# Patchline

**Reproducible vulnerability intelligence analytics with an evidence-first frontend.**

Patchline is a local-first security and data engineering project pairing archived **CISA Known Exploited Vulnerabilities (KEV)** catalog snapshots with **FIRST Exploit Prediction Scoring System (EPSS)** daily probability scores. It combines Python ingestion and validation, immutable source metadata, DuckDB, dbt models, versioned analytical exports, and the React/TypeScript **Spectral Index** website.

## Implemented

- **Source ingestion:** guarded KEV and EPSS ingestion, schema checks, row-count and snapshot provenance, with local archived inputs.
- **Warehouse and dbt:** DuckDB staging, a full CVE-universe KEV/EPSS join, analytical marts, reconciliation and source-lineage tests.
- **M03:** EPSS score coverage for the selected KEV catalog, including unmatched CVEs.
- **M04:** EPSS full-scored-population summary and five fixed probability bands.
- **M05:** KEV cohort membership across those same five bands plus an explicit unscored KEV category. Published in opt-in v2 exports, not yet consumed by the website.
- **Exports:** immutable, verified v1 bundles of **nine dataset artifacts** (M03/M04), with opt-in v2 bundles of **twelve** (adding M05); CSV, JSON, Parquet, and manifest SHA-256 metadata. Neither is a live vulnerability feed.
- **Spectral Index:** responsive Intelligence Atlas, interactive EPSS band details, nine-file evidence register, and Methods & Quality views. Vulnerability Explorer is explicitly a preview rather than an invented CVE database.
- **Quality gates:** Python tests, dbt data tests, frontend tests, and isolated Chromium/Playwright browser checks in GitHub Actions.

## Architecture

```text
Archived KEV / EPSS source files
            |
  Python validation and ingestion
            |
       DuckDB warehouse
            |
  dbt staging + CVE full outer join
            |
   M03 + M04 + M05 analytical marts
            |
  Verified v1 (M03/M04) or v2 (+ M05)
            |
  React / TypeScript Spectral Index (v1)
```

**Important data boundary:** the public demo uses an explicitly labeled **synthetic fixture**. Demo values must not be described as actual current exploitation activity. EPSS scores are model estimates, not observations of exploitation; KEV catalog inclusion is not evidence of exposure in any specific organization. The website displays manifest-recorded digests but does not perform browser-side cryptographic verification.

Versioned export usage and the v2 migration boundary are documented in [P5.1B exports](docs/exports-p51b.md).

## Reproduce the offline pipeline

Python 3.12 and [uv](https://docs.astral.sh/uv/) are required. From the repository root in PowerShell 5.1:

```powershell
uv sync --locked --python 3.12
$env:PATCHLINE_DUCKDB_PATH = Join-Path $env:TEMP ("patchline-ci-" + [guid]::NewGuid().ToString("N") + ".duckdb")
uv run --locked python -m patchline.fixtures.ci_warehouse create --output $env:PATCHLINE_DUCKDB_PATH
uv run --locked dbt run --project-dir dbt --profiles-dir dbt
uv run --locked dbt test --project-dir dbt --profiles-dir dbt
uv run --locked python -m patchline.fixtures.ci_warehouse verify-m05 --output $env:PATCHLINE_DUCKDB_PATH
uv run --locked pytest
uv run --locked ruff check .
```

These commands use a small, fully invented fixture and require no live feed download. The fixture creation command refuses to overwrite existing databases. Run the M03/M04 export workflow only after the source and dbt checks pass; see [export instructions](docs/exports-p34.md) and [M05 methodology](docs/dbt-p51-m05.md).

## Run Spectral Index

Node.js 22 is required. In a separate frontend terminal:

```powershell
Push-Location "apps/web"
npm ci
npm test
npm run build
npm run dev -- --strictPort
# In the frontend terminal, use Ctrl + C to stop the server.
```

For the reproducible browser suite, run `npx playwright install chromium` followed by `npm run test:e2e` from `apps/web`. The test runner creates and verifies a synthetic fixture and starts an isolated server. To view populated local demo pages outside the test suite, follow [frontend fixture setup](docs/frontend-p41.md). Do not commit generated data, fixtures, browser screenshots, or local warehouse files.

## Methodology and source credit

- [Architecture notes](docs/architecture.md)
- [M03 coverage](docs/dbt-p33-m03.md), [M04 distribution](docs/dbt-p33-m04.md), [M05 cohort analysis](docs/dbt-p51-m05.md)
- [Export and integrity contracts](docs/exports-p34-consumers.md)
- [Spectral Index](docs/frontend-p41b3.md)
- CISA KEV: https://github.com/cisagov/kev-data
- FIRST EPSS: https://www.first.org/epss/data

**Next:** migrate the Spectral Index consumer to opt-in v2 and introduce a clearly labeled scored-KEV versus full-EPSS comparison visualization.
