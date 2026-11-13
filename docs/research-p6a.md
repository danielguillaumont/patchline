# P6A3: Archived KEV and EPSS research brief

## Purpose

Produce an evidence-led, snapshot-specific Markdown research brief from an existing, verified v2 analytical export. The report compares the same five probability bands for the full scored EPSS population and the KEV cohort. It does not introduce another mart, change export contracts, or publish local source data.

The public Spectral Index website stays synthetic. The research brief is a separate, locally generated empirical output that must be reviewed before publication.

## Safety and interpretation

- The exporter must fully verify the bundle first, including recorded artifact SHA-256 digests and M05 reconciliation.
- The input must have classification `archived_source_snapshots` under `patchline.analytics-export.v2`.
- Both archived source snapshot IDs must be supplied explicitly and must match the manifest. The generator refuses synthetic fixtures and mismatched sources.
- The report preserves KEV and EPSS source dates, retrieval timestamps, populations, and the EPSS model version.
- The scored KEV cohort is included in the full EPSS population, so the percentages are descriptive and not independent-sample inference.
- EPSS is a model estimate about the next 30 days. KEV membership indicates known exploitation, not organizational exposure or a remediation priority.
- The output must be a new filename. The generator will not overwrite an existing report.
- The report does not fetch live data or modify the warehouse, archived snapshots, or public site.

## Local command (PowerShell 5.1)

From the repository root, with the real v2 export from P6A2 already verified:

```powershell
$kev = "41c8091ad62d508d6f8906ad5cd26b20efe551f7d51b95ecc8a6981fa640b4ea"
$epss = "1f57c666e70798638d84923302d2d54bc52b3da71e49984bc8f13e22291818e7"
$export = Join-Path $PWD "data\exports\p6a-real-2026-11-11-v2"
$output = Join-Path $PWD "data\reports\p6a-real-2026-11-11-cohort.md"
uv run --locked python -m patchline.research.case_study --export $export --output $output --kev-snapshot $kev --epss-snapshot $epss
```

`data/reports/` is ignored by Git. Confirm the generated report's complete content, especially source dates, denominators, and distribution values. Only then decide which aggregate findings should be promoted into `docs/research/` in a separate reviewed PR.

## Acceptance

- `uv run --locked pytest tests/test_case_study.py` passes.
- `uv run --locked ruff check src/patchline/research tests/test_case_study.py` passes.
- Existing Python tests, frontend code, and CI are unchanged.
- The generated report exists outside Git, uses the selected archived-source pair, and reconciles five band counts and the unscored KEV row.
- No raw datasets, generated exports, or DuckDB files are included in this source slice.
