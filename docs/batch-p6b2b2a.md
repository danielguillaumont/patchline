# P6B2B2A: Anchored batch journal genesis

## Purpose

Introduce a read-only-verifiable starting point for future transition history. An existing P6B2A run must remain `planned` at revision `0`. This slice creates a separate `journal/000000-genesis.json` file beneath the run's ignored workspace, never updating or replacing `run-state.json`.

`batch journal-init` anchors the original run state; `batch journal-status` checks the anchor against the current state bytes and canonical state content. Both commands fail closed on missing records, unsafe paths, changed state, malformed genesis, unexpected files, incomplete directories or a repeated initialization.

## Contract and boundaries

- The genesis entry records the source-pinned run identity, sequence `0`, revision `0`, status `planned` and all stages `not_started`.
- The entry contains SHA-256 digests for the original state bytes and canonical state JSON. Its own `entry_sha256` is calculated from canonical entry fields excluding the digest itself.
- Publication uses a new directory, fully flushed temporary file, and a no-overwrite hard link. An interrupted directory is not automatically repaired or removed.
- A local hash can detect accidental modification relative to the retained entry. It is **not** an authenticated signature or a protection against an adversary who can rewrite both records.
- The journal deliberately supports exactly one genesis entry in this slice. It does not persist transitions, execute stages, verify completion evidence, or mark any stage `running`, `failed` or `succeeded`.
- The existing P6B2A `batch status`, P6B2B1 pure transition contract, source archives, warehouse, exports, and public synthetic demo are unchanged.

## Windows PowerShell 5.1

From the repository root, after P6B2A initialized the original source pair:

```powershell
$runId = "batch-f2f915e3b023154e0db8bb14b2b043cd71988cb6a0a24b1bf3c3471839452f62"
uv run --locked python -m patchline batch journal-init --data-dir data --run-id $runId
uv run --locked python -m patchline batch journal-status --data-dir data --run-id $runId
```

**Do not initialize twice.** A second `journal-init` must fail without changing any existing content. A future slice can add append-only transition records with verified executor evidence before any success state is persisted.

## Acceptance

Run `uv run --locked pytest tests/test_batch_journal.py`, `uv run --locked ruff check .`, and `uv run --locked pytest`. Confirm the original state file SHA-256 remains unchanged before and after journal commands. Confirm the journal file and all local data remain Git-ignored.
