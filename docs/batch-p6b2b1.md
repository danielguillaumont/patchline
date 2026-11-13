# P6B2B1: Pure batch transition contract

## Purpose

This slice defines the rules for changing batch execution state before introducing any durable transition writer or executor. `patchline.batch.transitions` accepts a source-pinned P6B2A state record, validates its current lifecycle and revision, and generates an in-memory **transition proposal**.

**No command is introduced in this slice.** No stage runs, no state file is updated, and the existing `batch init` and `batch status` contracts are unchanged. In particular, the November 2026 run's `run-state.json` remains at `planned`, revision 0.

## Transition rules

- Stage ordering is `warehouse`, then `dbt`, then `export`. A stage cannot start before its predecessor has succeeded.
- Each stage progresses from `not_started` to `running` to `succeeded`, or from `running` to `failed`. Only one stage may run at a time.
- Run states are `planned`, `running`, `succeeded`, and `failed`. `failed` and `succeeded` are terminal for this contract. Automatic recovery is not claimed.
- Every proposal requires the caller's exact current revision, and its preview increments that revision by one. Stale revisions and duplicate starts are rejected.
- Completion proposals require a stage-specific 64-character lowercase SHA-256 evidence **reference**. The proposal deliberately reports `execution_verified: false`. This slice does not check file existence or verify any digest, so it cannot be used as evidence of completed processing.
- Failure proposals require a bounded uppercase error code, not an arbitrary exception message or sensitive local path.
- A proposal includes a digest of the input record and `persisted: false`. `preview_transition` confirms the proposal matches the input and returns a deep-copied, explicitly nonpersisted candidate state.

## Compatibility and safety

P6B2A's durable `patchline.batch-run.v1` record is **not replaced or migrated**. `batch status` continues to support only validated initial `planned` records; attempts to write previews over `run-state.json` are unsupported and unsafe. A proposal is not proof of execution, and any `succeeded` preview is hypothetical.

Future P6B2B2 work must design a separate no-overwrite transition journal and verify actual executor evidence before persisting stage completion. Do not enable a CLI operation that promotes a stage to succeeded based solely on metadata submitted by a caller.

## Acceptance

From Windows PowerShell 5.1, after applying the source slice:

```powershell
uv run --locked pytest tests/test_batch_transitions.py
uv run --locked ruff check .
uv run --locked pytest
```

Also confirm that the existing persisted `planned` run can still be read with `patchline batch status`, without changing its file hash. No raw source data, DuckDB database or export bundle should change.
