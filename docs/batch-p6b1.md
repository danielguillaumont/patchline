# P6B1: Source-pinned batch plan contract

## Scope

Patchline can now preview a deterministic batch run from two **explicitly selected** archived source snapshots. The first P6B1 slice introduces an offline, read-only `batch plan` command. It does not perform execution, create a workspace, persist run history, schedule jobs, or alter the existing single-pair DuckDB build.

The planner calls the same archive validation used by the existing warehouse builder. This includes SHA-256 checks, KEV schema and semantic validation, EPSS feed validation, manifest reconciliation and row-count checks. Unvalidated, missing or corrupted archived sources fail before a plan is printed.

## Local invocation

On Windows PowerShell 5.1, from the repository root:

```powershell
$kev = "41c8091ad62d508d6f8906ad5cd26b20efe551f7d51b95ecc8a6981fa640b4ea"
$epss = "1f57c666e70798638d84923302d2d54bc52b3da71e49984bc8f13e22291818e7"
uv run --locked python -m patchline batch plan --data-dir data --kev-snapshot $kev --epss-snapshot $epss
```

The JSON result includes the `patchline.batch-plan.v1` schema identifier, a stable content-addressed run ID, both source IDs, dates and counts, explicit `patchline.analytics-export.v2` intent, and reserved **proposed** target paths under ignored `data/runs/<run-id>/`. All stage fields are `not_started`. `status: planned_only` and `persisted: false` are deliberate: planning is not an execution record.

The same snapshots and planning contract produce the same run ID, irrespective of the local computer or invocation time. Running the command twice does not create any folders. If the calculated workspace already exists, planning fails closed instead of treating existing run artifacts as safe to overwrite.

## Current boundaries

- This is a contract and safety foundation, **not** a working orchestrator or historical warehouse.
- Paths refer to future local run outputs; their presence is not claimed.
- The command reads and validates locally archived files; it does not download live feeds.
- No source data or database files are added to Git, and the public Spectral Index demo remains synthetic.
- The next slice should implement immutable run state and replay behaviour with explicit, separately tested transitions before executing DuckDB, dbt and exports.

## Acceptance

`uv run --locked pytest tests/test_batch_plan.py`, `uv run --locked pytest` and `uv run --locked ruff check .` must pass. Preview the command against the existing verified November 2026 archive pair. No workspace or git-ignored data files should change during the preview.
