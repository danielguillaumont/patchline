# P6B2A: Durable planned-run reservation

## Purpose

This slice extends the P6B1 source-pinned, read-only planner with two explicit commands:

- `batch init`: revalidate a selected archived KEV/EPSS pair, reserve a new deterministic run directory and publish one durable `run-state.json` record.
- `batch status`: inspect and validate that local planned-run record by its exact run ID.

No warehouse build, dbt processing, export creation, scheduler, or stage transition is introduced in this slice. The public Spectral Index website remains a separate synthetic demonstration.

## Contract and safety boundaries

- Run identity is the existing P6B1 SHA-256 identity derived from both source snapshot IDs and the analytics contract. P6B2A does not redefine it.
- A new record uses `patchline.batch-run.v1`, `status: planned`, `persisted: true`, `revision: 0`, and `warehouse`, `dbt`, `export` all `not_started`.
- The record embeds the original read-only `patchline.batch-plan.v1` result, including exact source IDs, dates, counts and proposed paths. The planner itself still returns `planned_only` and `persisted: false` before initialization.
- The run directory is created exclusively under Git-ignored `data/runs/<run-id>/`. A temporary fully flushed JSON file is published through a no-overwrite hard link to `run-state.json`.
- If an interruption leaves a directory without a valid state file, it is intentionally **not** deleted, automatically repaired, or silently reused. An existing workspace is a hard failure.
- A completed record is only an initialization record. It does **not** claim that a data pipeline ran or that analytics were verified.
- `batch status` validates the stored contract, identity, stage values and expected workspace paths. It is not a cryptographic signature of local metadata or revalidation of upstream archives.
- Existing P6A warehouse, v2 export, research report, and raw snapshots are left unchanged. No local data is committed.

## Windows PowerShell 5.1

From the repository root with archived source snapshots available:

```powershell
$kev = "41c8091ad62d508d6f8906ad5cd26b20efe551f7d51b95ecc8a6981fa640b4ea"
$epss = "1f57c666e70798638d84923302d2d54bc52b3da71e49984bc8f13e22291818e7"
uv run --locked python -m patchline batch init --data-dir data --kev-snapshot $kev --epss-snapshot $epss
```

To inspect that persisted record later:

```powershell
$runId = "batch-f2f915e3b023154e0db8bb14b2b043cd71988cb6a0a24b1bf3c3471839452f62"
uv run --locked python -m patchline batch status --data-dir data --run-id $runId
```

Running `batch init` twice with the same inputs must fail without altering the existing record. `batch plan` also refuses an existing run workspace, as designed in P6B1. To plan a different source pair, specify its source IDs; do not edit recorded IDs manually.

## Acceptance and next slice

Run the focused Python tests, the full Python suite and Ruff. On a clean machine, `init` must create only one run directory and state record; `status` must return that record; an immediate second `init` must fail closed. Only use the real archives when the tests pass. Do not stage any files in `data/runs/`.

P6B2B will introduce tested state transitions and recovery controls before P6B2C executes DuckDB/dbt/exports. No P6B2A record can become `running`, `succeeded`, or `failed` through this interface.
