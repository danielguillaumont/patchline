# P4.1A: Spectral Index Frontend Foundation

First frontend slice uses React, TypeScript and Vite, under `apps/web`. Node.js 22 is required. The Python/dbt source pipeline is untouched.

## Important data boundary

`apps/web/public/demo` is **not checked into Git**. The website starts with a no-data explanatory state and never falls back to fabricated numbers. Create a verified synthetic export bundle locally using the existing `patchline.fixtures.ci_warehouse` and `patchline.exports.analytics` commands, then copy **only** `manifest.json` and the three M03/M04 `.json` datasets from the verified bundle into `apps/web/public/demo`. Do not copy your real/source archives into the public site. Do not publish source data without explicit disclosure/review.

### Reproduce locally (PowerShell 5.1)

1. Run `npm install --prefix apps/web` to generate `apps/web/package-lock.json`, which should be staged with the source. `npm ci --prefix apps/web` is thereafter the reproducible install path.
2. Run `npm test --prefix apps/web` (six contract tests) and `npm run build --prefix apps/web` (TypeScript + Vite).
3. Create a synthetic DuckDB fixture in Windows Temp with `uv run --locked python -m patchline.fixtures.ci_warehouse create --output <TEMP_PATH>`; assign `$env:PATCHLINE_DUCKDB_PATH` to that full path, then run `uv run --locked dbt run --project-dir dbt --profiles-dir dbt` and `uv run --locked dbt test --project-dir dbt --profiles-dir dbt`.
4. Create a fresh export directory in Windows Temp with `uv run --locked python -m patchline.exports.analytics create --database <TEMP_PATH> --output <EXPORT_PATH>` and verify with `uv run --locked python -m patchline.exports.analytics verify --output <EXPORT_PATH>`.
5. Copy `manifest.json`, `m03_epss_coverage_of_kev.json`, `m04_epss_population_summary.json`, `m04_epss_score_bands.json` to `apps/web/public/demo`. This directory is ignored from Git. Run `npm run dev --prefix apps/web` and open `http://127.0.0.1:5173/`.

**Data integrity**: the frontend applies structural and arithmetic checks and displays export classification. It does not verify SHA-256 in the browser. Python verification must occur before copy. Local Vite serves those JSON files as public content. Never place private or unreviewed records there.

## Limits

- Atlas presents M03/M04 only, no KEV additions timeline (not yet implemented).
- Explorer is a deliberate no-data preview until an approved CVE-level export exists.
- This candidate is not a visual-review approval. See `docs/design/spectral-index-p41-layout-review.md`.
- Production CI for frontend should be added in the next integration slice after package lock generation and local build verification.
