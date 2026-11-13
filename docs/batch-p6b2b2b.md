# P6B2B2B: Append-only transition proposal events

## Purpose

This slice adds an **internal-only append-only proposal log** anchored to the verified P6B2B2A journal genesis. Each proposal event is stored as a new content-hashed file beneath `data/runs/<run-id>/proposal-events/`. Events are chain-linked through the previous entry's digest and replayed against P6B2B1's pure transition contract on inspection.

**These are hypothetical proposals, not actual pipeline state transitions.** The P6B2A `run-state.json` remains `planned` at revision 0. The P6B2B2A journal genesis remains untouched. No stage is executed; no trusted stage-evidence verifier exists yet. Even a syntactically valid `complete` proposal provides no proof that a file exists or that processing succeeded.

## Safety guarantees

- Read and validate the original planned state and genesis before reading or appending events.
- Entries have sequential names (`000001-proposal.json`, etc.), a previous-entry SHA-256 reference, and a hash of canonical event metadata.
- Fully flush new entries and publish with a no-overwrite hard link. A concurrent attempt to publish the same sequence fails instead of overwriting.
- Verify every existing event's complete structure, hash link, numbering, and logical transition via the existing pure proposal validator.
- Refuse gaps, malformed JSON, unexpected files, changed metadata, symlinks, or an empty/incomplete event directory.
- Cap a hypothetical single-pass lifecycle at six events (three stages, each started and completed). No retries, migration, scheduler or recovery is claimed.
- Keep the real journal and original run state out of version control and unchanged.

## Important boundary

There is intentionally **no CLI to append proposals**. `patchline.batch.proposal_events` is an internal tested API for exercising and verifying the storage contract with offline synthetic states. This is not a job runner. P6B2C must implement verified stage execution and evidence validation before any actual run-progress writes are enabled. A SHA-256 reference supplied by a caller is not proof of execution.

A verified proposal-log result reports `verified_proposals_only`, `execution_verified: false`, `persisted_run_progress: false`, and the original `planned` revision. The existing `batch journal-status` command remains compatible because the proposal log lives alongside the genesis journal, not within it.

## Validation

On Windows PowerShell 5.1 from the repository root:

```powershell
uv run --locked pytest tests/test_batch_proposal_events.py
uv run --locked ruff check .
uv run --locked pytest
```

Also call `batch journal-status` against the real November 2026 planned run, confirming exactly one genesis entry and revision zero. **Do not write proposal events to the real run for this slice.** The offline tests exercise all writes in disposable temporary directories.
