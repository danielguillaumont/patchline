"""Pure transition proposals for source-pinned batch runs.

P6B2B1 is a fail-closed, in-memory contract only. Neither this module nor its
previews write a state file, execute a stage, or verify an output artifact.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

SCHEMA_ID = "patchline.batch-transition-proposal.v1"
RUN_SCHEMA_ID = "patchline.batch-run.v1"
PLAN_SCHEMA_ID = "patchline.batch-plan.v1"
STAGES = ("warehouse", "dbt", "export")
STAGE_STATES = {"not_started", "running", "succeeded", "failed"}
ACTIONS = {"start", "complete", "fail"}
RUN_ID = re.compile(r"batch-[0-9a-f]{64}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


class TransitionError(ValueError):
    """Proposed lifecycle transition is invalid or unsafe."""


def _canonical(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TransitionError("Run state is not valid canonical JSON") from exc


def _validate_state(state: dict[str, Any]) -> None:
    """Validate lifecycle invariants without treating a preview as durable state."""
    if not isinstance(state, dict):
        raise TransitionError("Expected a run-state object")
    if state.get("schema_id") != RUN_SCHEMA_ID:
        raise TransitionError("Unexpected run-state schema")
    run_id = state.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise TransitionError("Invalid run identifier")
    if type(state.get("revision")) is not int or state["revision"] < 0:
        raise TransitionError("Invalid run revision")
    if type(state.get("persisted")) is not bool:
        raise TransitionError("Missing persistence classification")
    plan = state.get("plan")
    if not isinstance(plan, dict) or plan.get("schema_id") != PLAN_SCHEMA_ID:
        raise TransitionError("Missing source-pinned plan")
    if plan.get("run_id") != run_id:
        raise TransitionError("Run identifier and plan disagree")
    if plan.get("status") != "planned_only" or plan.get("persisted") is not False:
        raise TransitionError("Stored plan must remain a planning-only contract")
    if plan.get("stages") != {key: "not_started" for key in STAGES}:
        raise TransitionError("Original source-pinned plan must remain unchanged")
    stages = state.get("stages")
    if not isinstance(stages, dict) or set(stages) != set(STAGES):
        raise TransitionError("Expected exactly three stage states")
    if any(status not in STAGE_STATES for status in stages.values()):
        raise TransitionError("Unrecognized stage state")
    if stages["dbt"] != "not_started" and stages["warehouse"] != "succeeded":
        raise TransitionError("dbt cannot precede warehouse completion")
    if stages["export"] != "not_started" and stages["dbt"] != "succeeded":
        raise TransitionError("Export cannot precede dbt completion")
    status = state.get("status")
    statuses = list(stages.values())
    if status == "planned":
        if any(x != "not_started" for x in statuses) or state["revision"] != 0:
            raise TransitionError("Planned run must be revision zero and untouched")
    elif status == "running":
        if "failed" in statuses or all(x == "succeeded" for x in statuses):
            raise TransitionError("Inconsistent running state")
        if statuses.count("running") > 1 or not any(x != "not_started" for x in statuses):
            raise TransitionError("Inconsistent stage progress")
    elif status == "failed":
        if statuses.count("failed") != 1 or "running" in statuses:
            raise TransitionError("Failed run must identify one failed stage")
    elif status == "succeeded":
        if any(x != "succeeded" for x in statuses):
            raise TransitionError("A successful run requires all stages completed")
    else:
        raise TransitionError("Unknown lifecycle status")
    if status != "planned" and state["revision"] == 0:
        raise TransitionError("Progress cannot have zero revision")
    _canonical(state)


def _evidence(action: str, stage: str, evidence: object) -> dict[str, str] | None:
    if action == "start":
        if evidence is not None:
            raise TransitionError("Starting a stage must not assert completion evidence")
        return None
    if action == "complete":
        if not isinstance(evidence, dict) or set(evidence) != {"stage", "sha256"}:
            raise TransitionError("Completion requires stage-specific evidence metadata")
        digest = evidence.get("sha256")
        if evidence.get("stage") != stage or not isinstance(digest, str):
            raise TransitionError("Completion evidence does not match stage")
        if not DIGEST.fullmatch(digest):
            raise TransitionError("Completion evidence digest must be lowercase SHA-256")
        return {"stage": stage, "sha256": digest}
    if action == "fail":
        if not isinstance(evidence, dict) or set(evidence) != {"error_code"}:
            raise TransitionError("Failure requires a bounded error code")
        code = evidence.get("error_code")
        if not isinstance(code, str) or not ERROR_CODE.fullmatch(code):
            raise TransitionError("Unsafe failure error code")
        return {"error_code": code}
    raise TransitionError("Unsupported transition action")


def propose_transition(
    state: dict[str, Any],
    *,
    action: str,
    stage: str,
    expected_revision: int,
    evidence: object = None,
) -> dict[str, Any]:
    """Produce a deterministic, NONPERSISTED lifecycle proposal.

    A digest in a proposal is metadata supplied by a future trusted executor;
    this function never claims to have opened, checked or verified that file.
    """
    _validate_state(state)
    if type(expected_revision) is not int or expected_revision != state["revision"]:
        raise TransitionError("Stale or invalid expected revision")
    if (
        not isinstance(action, str)
        or action not in ACTIONS
        or not isinstance(stage, str)
        or stage not in STAGES
    ):
        raise TransitionError("Unknown transition action or stage")
    if state["status"] in {"failed", "succeeded"}:
        raise TransitionError("Terminal run cannot transition")
    record = _evidence(action, stage, evidence)
    current = state["stages"]
    if action == "start":
        if current[stage] != "not_started":
            raise TransitionError("Stage already started or completed")
        index = STAGES.index(stage)
        if index and current[STAGES[index - 1]] != "succeeded":
            raise TransitionError("Previous stage has not succeeded")
        if "running" in current.values():
            raise TransitionError("Only one stage may run at a time")
        next_stage = "running"
    else:
        if current[stage] != "running":
            raise TransitionError("Stage is not running")
        next_stage = "succeeded" if action == "complete" else "failed"
    next_stages = {name: (next_stage if name == stage else current[name]) for name in STAGES}
    next_status = (
        "failed"
        if action == "fail"
        else "succeeded"
        if all(value == "succeeded" for value in next_stages.values())
        else "running"
    )
    return {
        "schema_id": SCHEMA_ID,
        "run_id": state["run_id"],
        "source_state_sha256": hashlib.sha256(_canonical(state)).hexdigest(),
        "action": action,
        "stage": stage,
        "expected_revision": expected_revision,
        "next_revision": expected_revision + 1,
        "next_status": next_status,
        "next_stages": next_stages,
        "evidence_metadata": record,
        "persisted": False,
        "execution_verified": False,
    }


def preview_transition(state: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    """Preview a validated proposal in memory; never write or overwrite run-state.json."""
    if not isinstance(proposal, dict):
        raise TransitionError("Transition proposal must be an object")
    expected = propose_transition(
        state,
        action=proposal.get("action"),
        stage=proposal.get("stage"),
        expected_revision=proposal.get("expected_revision"),
        evidence=proposal.get("evidence_metadata"),
    )
    if proposal != expected:
        raise TransitionError("Transition proposal differs from verified input")
    preview = deepcopy(state)
    preview["revision"] = expected["next_revision"]
    preview["status"] = expected["next_status"]
    preview["stages"] = deepcopy(expected["next_stages"])
    preview["persisted"] = False
    _validate_state(preview)
    return preview
