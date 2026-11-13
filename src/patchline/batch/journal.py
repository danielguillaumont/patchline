"""Create and verify an anchored, no-overwrite genesis for future batch history.

The existing P6B2A run-state.json remains the only persisted lifecycle state.
No transition or execution outcome may be written by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from patchline.batch.state import BatchStateError, _workspace, read_run

SCHEMA_ID = "patchline.batch-journal-genesis.v1"
JOURNAL_FOLDER = "journal"
GENESIS_FILE = "000000-genesis.json"
MAX_GENESIS_BYTES = 16 * 1024
EXPECTED_FIELDS = {
    "schema_id",
    "run_id",
    "sequence",
    "revision",
    "status",
    "stages",
    "source_state_sha256",
    "source_state_canonical_sha256",
    "previous_entry_sha256",
    "entry_sha256",
}


class BatchJournalError(ValueError):
    """A journal cannot be safely initialized or verified."""


def _canonical(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise BatchJournalError("Invalid canonical journal metadata") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _state_and_path(data_dir: Path, run_id: str) -> tuple[dict[str, Any], Path, Path]:
    try:
        state = read_run(data_dir, run_id=run_id)
        _, run_dir = _workspace(data_dir, run_id)
    except (BatchStateError, OSError) as exc:
        raise BatchJournalError(f"Invalid existing planned run: {exc}") from exc
    if state["status"] != "planned" or state["revision"] != 0:
        raise BatchJournalError("Journal genesis requires the original planned revision")
    state_path = run_dir / "run-state.json"
    if state_path.is_symlink() or not state_path.is_file():
        raise BatchJournalError("Unsafe original state file")
    return state, run_dir, state_path


def _genesis(state: dict[str, Any], state_bytes: bytes) -> dict[str, Any]:
    fields = {
        "schema_id": SCHEMA_ID,
        "run_id": state["run_id"],
        "sequence": 0,
        "revision": 0,
        "status": "planned",
        "stages": state["stages"],
        "source_state_sha256": _sha256(state_bytes),
        "source_state_canonical_sha256": _sha256(_canonical(state)),
        "previous_entry_sha256": None,
    }
    return {**fields, "entry_sha256": _sha256(_canonical(fields))}


def _publish_new(path: Path, record: dict[str, Any]) -> None:
    encoded = (json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_GENESIS_BYTES:
        raise BatchJournalError("Genesis record exceeds the byte limit")
    descriptor, temporary = tempfile.mkstemp(prefix=".patchline-genesis-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise BatchJournalError("Genesis already exists; refusing overwrite") from exc
    finally:
        Path(temporary).unlink(missing_ok=True)


def initialize_journal(data_dir: Path, *, run_id: str) -> dict[str, Any]:
    """Anchor one existing planned run without changing its state file.

    An interrupted initialization may leave an incomplete journal directory.
    That directory must be investigated; it is never reused or removed here.
    """
    state, run_dir, state_path = _state_and_path(data_dir, run_id)
    journal = run_dir / JOURNAL_FOLDER
    if journal.exists() or journal.is_symlink():
        raise BatchJournalError("Journal already exists; refusing replay")
    state_bytes = state_path.read_bytes()
    if len(state_bytes) > 64 * 1024:
        raise BatchJournalError("Original state exceeds size limit")
    record = _genesis(state, state_bytes)
    try:
        journal.mkdir(exist_ok=False)
    except FileExistsError as exc:
        raise BatchJournalError("Journal already exists; refusing replay") from exc
    except OSError as exc:
        raise BatchJournalError(f"Unable to reserve journal directory: {exc}") from exc
    try:
        if journal.is_symlink() or not journal.is_dir():
            raise BatchJournalError("Journal directory became unsafe")
        # Detect a state-file change between inspection and publication.
        if state_path.read_bytes() != state_bytes:
            raise BatchJournalError("Original state changed during journal initialization")
        _publish_new(journal / GENESIS_FILE, record)
    except OSError as exc:
        raise BatchJournalError(f"Unable to publish journal genesis: {exc}") from exc
    return {
        "status": "initialized_genesis_only",
        "run_id": run_id,
        "entries": 1,
        "revision": 0,
        "entry_sha256": record["entry_sha256"],
        "journal_file": str(journal / GENESIS_FILE),
        "execution_verified": False,
    }


def inspect_journal(data_dir: Path, *, run_id: str) -> dict[str, Any]:
    """Validate the exact genesis entry and its pinned original state bytes."""
    state, run_dir, state_path = _state_and_path(data_dir, run_id)
    journal = run_dir / JOURNAL_FOLDER
    if journal.is_symlink() or not journal.is_dir():
        raise BatchJournalError("Missing or unsafe journal directory")
    entries = list(journal.iterdir())
    if len(entries) != 1 or entries[0].name != GENESIS_FILE:
        raise BatchJournalError("Missing or unexpected journal entries")
    entry = entries[0]
    if entry.is_symlink() or not entry.is_file():
        raise BatchJournalError("Unsafe genesis entry")
    size = entry.stat().st_size
    if size <= 0 or size > MAX_GENESIS_BYTES:
        raise BatchJournalError("Genesis entry size is invalid")
    try:
        record = json.loads(entry.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise BatchJournalError("Unreadable journal genesis") from exc
    if not isinstance(record, dict) or set(record) != EXPECTED_FIELDS:
        raise BatchJournalError("Unexpected journal genesis structure")
    if (
        record["schema_id"] != SCHEMA_ID
        or record["run_id"] != run_id
        or type(record["sequence"]) is not int
        or record["sequence"] != 0
        or type(record["revision"]) is not int
        or record["revision"] != 0
        or record["status"] != "planned"
        or record["stages"] != state["stages"]
        or record["previous_entry_sha256"] is not None
    ):
        raise BatchJournalError("Journal genesis contract mismatch")
    try:
        state_bytes = state_path.read_bytes()
    except OSError as exc:
        raise BatchJournalError("Cannot read original state file") from exc
    expected = _genesis(state, state_bytes)
    if record != expected:
        raise BatchJournalError("Journal genesis or original state integrity mismatch")
    return {
        "status": "verified_genesis_only",
        "run_id": run_id,
        "entries": 1,
        "revision": 0,
        "entry_sha256": record["entry_sha256"],
        "journal_file": str(entry),
        "execution_verified": False,
    }
