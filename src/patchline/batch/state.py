"""Persist and inspect planned batch runs without executing any stages."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchline.batch.plan import (
    ANALYTICS_CONTRACT,
    BatchPlanError,
    plan_batch,
)
from patchline.batch.plan import (
    SCHEMA_ID as PLAN_SCHEMA_ID,
)

SCHEMA_ID = "patchline.batch-run.v1"
RUN_ID = re.compile(r"batch-[a-f0-9]{64}\Z")
STATE_FILENAME = "run-state.json"
MAX_STATE_BYTES = 64 * 1024
STAGES = ("warehouse", "dbt", "export")


class BatchStateError(ValueError):
    """A proposed run cannot be reserved or an existing record is unsafe."""


def _identity_run_id(plan: dict[str, Any]) -> str:
    """Recompute the P6B1 identity from its source-pinned contract."""
    try:
        identity = {
            "schema_id": PLAN_SCHEMA_ID,
            "analytics_contract": ANALYTICS_CONTRACT,
            "kev_snapshot_id": plan["sources"]["kev"]["snapshot_id"],
            "epss_snapshot_id": plan["sources"]["epss"]["snapshot_id"],
        }
        for name in ("kev_snapshot_id", "epss_snapshot_id"):
            if not re.fullmatch(r"[a-f0-9]{64}", identity[name]):
                raise BatchStateError("Invalid source identity in stored plan")
    except (KeyError, TypeError, ValueError) as exc:
        raise BatchStateError("Missing source identity in stored plan") from exc
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "batch-" + hashlib.sha256(canonical).hexdigest()


def _workspace(data_dir: Path, run_id: str) -> tuple[Path, Path]:
    if not RUN_ID.fullmatch(run_id):
        raise BatchStateError("Run ID must be batch- followed by 64 lowercase hex digits")
    root = data_dir.resolve() / "runs"
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise BatchStateError("Run workspace root is not a normal directory")
    return root, root / run_id


def _publish_new(path: Path, value: dict[str, Any]) -> None:
    """Publish a fully flushed JSON file using a no-overwrite hard link."""
    encoded = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_STATE_BYTES:
        raise BatchStateError("Planned run record exceeds size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=".patchline-run-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise BatchStateError("Run state already exists; refusing overwrite") from exc
    finally:
        Path(temporary).unlink(missing_ok=True)


def initialize_run(
    data_dir: Path, *, kev_snapshot: str, epss_snapshot: str
) -> dict[str, Any]:
    """Revalidate archives and reserve one new run with a durable planned state.

    An interruption after directory creation leaves an incomplete workspace.
    It is intentionally not deleted or automatically reused on the next call.
    """
    try:
        plan = plan_batch(
            data_dir, kev_snapshot=kev_snapshot, epss_snapshot=epss_snapshot
        )
    except BatchPlanError as exc:
        raise BatchStateError(f"Batch planning failed: {exc}") from exc

    run_id = plan["run_id"]
    root, run_dir = _workspace(data_dir, run_id)
    if Path(plan["targets"]["run_directory"]) != run_dir:
        raise BatchStateError("Planner and run workspace paths disagree")
    if run_dir.exists() or run_dir.is_symlink():
        raise BatchStateError("Run directory already exists; refusing replay")

    # This is the only accepted constructor path for a v1 record. No stages run.
    stamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    record: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "run_id": run_id,
        "status": "planned",
        "persisted": True,
        "revision": 0,
        "created_at_utc": stamp,
        "updated_at_utc": stamp,
        "stages": {stage: "not_started" for stage in STAGES},
        "plan": plan,
    }

    try:
        root.mkdir(exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise BatchStateError("Run workspace root changed unexpectedly")
        run_dir.mkdir(exist_ok=False)
    except FileExistsError as exc:
        raise BatchStateError("Run directory already exists; refusing replay") from exc
    except OSError as exc:
        raise BatchStateError(f"Run workspace reservation failed: {exc}") from exc
    try:
        _publish_new(run_dir / STATE_FILENAME, record)
    except OSError as exc:
        raise BatchStateError(f"Unable to publish run state: {exc}") from exc

    return record


def _check_utc_stamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BatchStateError("Run timestamp must be UTC")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BatchStateError("Invalid run timestamp") from exc
    if timestamp.utcoffset() != UTC.utcoffset(None):
        raise BatchStateError("Run timestamp must be UTC")


def read_run(data_dir: Path, *, run_id: str) -> dict[str, Any]:
    """Fail closed on missing, incomplete or modified v1 planned-state records."""
    root, run_dir = _workspace(data_dir, run_id)
    if not root.is_dir() or run_dir.is_symlink() or not run_dir.is_dir():
        raise BatchStateError("Run directory missing or unsafe")
    state_path = run_dir / STATE_FILENAME
    if state_path.is_symlink() or not state_path.is_file():
        raise BatchStateError("Missing or unsafe run state file")
    if state_path.stat().st_size > MAX_STATE_BYTES:
        raise BatchStateError("Run state file exceeds size limit")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise BatchStateError("Unreadable run state") from exc
    if not isinstance(state, dict) or set(state) != {
        "schema_id", "run_id", "status", "persisted", "revision", "created_at_utc",
        "updated_at_utc", "stages", "plan",
    }:
        raise BatchStateError("Unexpected run state structure")
    if (state["schema_id"] != SCHEMA_ID or state["run_id"] != run_id):
        raise BatchStateError("Run state identity mismatch")
    if (state["status"] != "planned" or state["persisted"] is not True):
        raise BatchStateError("Unsupported run status for state contract v1")
    if type(state["revision"]) is not int or state["revision"] != 0:
        raise BatchStateError("Unexpected run state revision")
    _check_utc_stamp(state["created_at_utc"])
    _check_utc_stamp(state["updated_at_utc"])
    if state["created_at_utc"] != state["updated_at_utc"]:
        raise BatchStateError("Unexpected planned-run timestamp change")
    if state["stages"] != {stage: "not_started" for stage in STAGES}:
        raise BatchStateError("Planned run must not report executed stages")
    plan = state["plan"]
    if not isinstance(plan, dict):
        raise BatchStateError("Missing stored batch plan")
    if (
        plan.get("schema_id") != PLAN_SCHEMA_ID
        or plan.get("analytics_contract") != ANALYTICS_CONTRACT
        or plan.get("status") != "planned_only"
        or plan.get("persisted") is not False
        or plan.get("run_id") != run_id
        or plan.get("stages") != state["stages"]
        or _identity_run_id(plan) != run_id
    ):
        raise BatchStateError("Stored plan does not match run identity")
    targets = plan.get("targets")
    if not isinstance(targets, dict) or targets != {
        "run_directory": str(run_dir),
        "warehouse": str(run_dir / "warehouse" / "patchline.duckdb"),
        "v2_export": str(run_dir / "exports" / "v2"),
    }:
        raise BatchStateError("Stored plan targets do not match run workspace")
    return state
