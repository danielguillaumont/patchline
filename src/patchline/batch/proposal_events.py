"""Append-only, hash-linked transition PROPOSALS, not execution records.

The P6B2A run-state.json and P6B2B2A genesis remain unchanged. Even a
complete six-proposal chain is hypothetical and never proves stage execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from patchline.batch.journal import BatchJournalError, inspect_journal
from patchline.batch.state import BatchStateError, _workspace, read_run
from patchline.batch.transitions import TransitionError, preview_transition, propose_transition

SCHEMA_ID = "patchline.batch-proposal-event.v1"
PROPOSAL_FOLDER = "proposal-events"
MAX_EVENTS = 6  # A stage may start and complete/fail exactly once; no retries yet.
MAX_EVENT_BYTES = 32 * 1024
ENTRY_FIELDS = {
    "schema_id",
    "run_id",
    "sequence",
    "previous_entry_sha256",
    "proposal",
    "entry_sha256",
}
HASH = re.compile(r"[0-9a-f]{64}\Z")


class BatchProposalLogError(ValueError):
    """A transition proposal cannot be recorded or verified safely."""


def _canonical(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise BatchProposalLogError("Proposal event is not valid canonical JSON") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_new(path: Path, record: dict[str, Any]) -> None:
    """Flush fully before an atomic no-overwrite publication to a new filename."""
    content = (json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    if len(content) > MAX_EVENT_BYTES:
        raise BatchProposalLogError("Proposal event exceeds byte limit")
    descriptor, temporary = tempfile.mkstemp(prefix=".patchline-proposal-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise BatchProposalLogError(
                "Proposal sequence already exists; refusing overwrite"
            ) from exc
    finally:
        Path(temporary).unlink(missing_ok=True)


def _read_chain(
    data_dir: Path, run_id: str
) -> tuple[dict[str, Any], Path, str, int]:
    """Reconstruct hypothetical proposals from the original planned revision."""
    try:
        initial = read_run(data_dir, run_id=run_id)
        genesis = inspect_journal(data_dir, run_id=run_id)
        _, run_dir = _workspace(data_dir, run_id)
    except (BatchStateError, BatchJournalError, OSError) as exc:
        raise BatchProposalLogError(f"Original state or genesis is invalid: {exc}") from exc
    if initial["status"] != "planned" or initial["revision"] != 0:
        raise BatchProposalLogError("Proposal log requires the original planned state")
    if genesis["status"] != "verified_genesis_only" or genesis["revision"] != 0:
        raise BatchProposalLogError("Genesis is not verified at revision zero")
    previous = genesis["entry_sha256"]
    if not isinstance(previous, str) or not HASH.fullmatch(previous):
        raise BatchProposalLogError("Invalid anchored genesis digest")
    folder = run_dir / PROPOSAL_FOLDER
    if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
        raise BatchProposalLogError("Unsafe proposal-event directory")
    if not folder.exists():
        return initial, folder, previous, 0

    entries = sorted(folder.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > MAX_EVENTS:
        raise BatchProposalLogError("Incomplete or oversized proposal-event chain")
    state = initial
    for sequence, entry in enumerate(entries, start=1):
        if entry.name != f"{sequence:06d}-proposal.json":
            raise BatchProposalLogError("Unexpected, missing or out-of-order proposal entry")
        if entry.is_symlink() or not entry.is_file():
            raise BatchProposalLogError("Unsafe proposal entry")
        size = entry.stat().st_size
        if size <= 0 or size > MAX_EVENT_BYTES:
            raise BatchProposalLogError("Proposal entry size is invalid")
        try:
            record = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise BatchProposalLogError("Unreadable proposal event") from exc
        if not isinstance(record, dict) or set(record) != ENTRY_FIELDS:
            raise BatchProposalLogError("Unexpected proposal event structure")
        body = {key: record[key] for key in ENTRY_FIELDS if key != "entry_sha256"}
        if (
            record["schema_id"] != SCHEMA_ID
            or record["run_id"] != run_id
            or type(record["sequence"]) is not int
            or record["sequence"] != sequence
            or record["previous_entry_sha256"] != previous
            or record["entry_sha256"] != _sha256(_canonical(body))
        ):
            raise BatchProposalLogError("Proposal chain integrity mismatch")
        proposal = record["proposal"]
        if not isinstance(proposal, dict):
            raise BatchProposalLogError("Malformed transition proposal")
        if (
            proposal.get("persisted") is not False
            or proposal.get("execution_verified") is not False
        ):
            raise BatchProposalLogError("Proposal incorrectly claims execution or persistence")
        try:
            state = preview_transition(state, proposal)
        except (TransitionError, ValueError, TypeError) as exc:
            raise BatchProposalLogError(f"Invalid proposed transition sequence: {exc}") from exc
        previous = record["entry_sha256"]
    return state, folder, previous, len(entries)


def inspect_proposal_events(data_dir: Path, *, run_id: str) -> dict[str, Any]:
    """Verify the hash chain; report only hypothetical proposals, not run progress."""
    state, folder, previous, count = _read_chain(data_dir, run_id)
    return {
        "status": "verified_proposals_only",
        "run_id": run_id,
        "entries": count,
        "preview_revision": state["revision"],
        "last_entry_sha256": previous,
        "proposal_directory": str(folder),
        "original_run_status": "planned",
        "original_run_revision": 0,
        "execution_verified": False,
        "persisted_run_progress": False,
    }


def append_proposal_event(
    data_dir: Path,
    *,
    run_id: str,
    action: str,
    stage: str,
    expected_revision: int,
    evidence: object = None,
) -> dict[str, Any]:
    """Persist a hypothetical proposal as a new hash-linked file.

    Internal API only. No CLI is exposed, since no trusted executor exists yet.
    Completion evidence is metadata ONLY, never inspected or authenticated here.
    """
    state, folder, previous, count = _read_chain(data_dir, run_id)
    if count >= MAX_EVENTS:
        raise BatchProposalLogError("Proposal-event chain is at its limit")
    try:
        proposal = propose_transition(
            state,
            action=action,
            stage=stage,
            expected_revision=expected_revision,
            evidence=evidence,
        )
        preview_transition(state, proposal)
    except (TransitionError, ValueError, TypeError) as exc:
        raise BatchProposalLogError(f"Invalid proposed transition: {exc}") from exc
    if proposal["persisted"] is not False or proposal["execution_verified"] is not False:
        raise BatchProposalLogError("Proposal must not claim verified execution")
    sequence = count + 1
    body: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "run_id": run_id,
        "sequence": sequence,
        "previous_entry_sha256": previous,
        "proposal": proposal,
    }
    record = {**body, "entry_sha256": _sha256(_canonical(body))}
    if not folder.exists():
        try:
            folder.mkdir(exist_ok=False)
        except FileExistsError as exc:
            raise BatchProposalLogError("Proposal directory appeared concurrently") from exc
        except OSError as exc:
            raise BatchProposalLogError(f"Could not reserve proposal directory: {exc}") from exc
    if folder.is_symlink() or not folder.is_dir():
        raise BatchProposalLogError("Unsafe proposal directory")
    target = folder / f"{sequence:06d}-proposal.json"
    try:
        _write_new(target, record)
    except OSError as exc:
        raise BatchProposalLogError(f"Could not publish proposal event: {exc}") from exc
    return {
        "status": "appended_proposal_only",
        "run_id": run_id,
        "sequence": sequence,
        "preview_revision": proposal["next_revision"],
        "entry_sha256": record["entry_sha256"],
        "execution_verified": False,
        "persisted_run_progress": False,
    }
