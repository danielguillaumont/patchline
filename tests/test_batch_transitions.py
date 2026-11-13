"""P6B2B1 pure lifecycle contract tests, with no writes or stage execution."""

import json
from copy import deepcopy

import pytest

from patchline.batch.transitions import (
    TransitionError,
    preview_transition,
    propose_transition,
)

RUN_ID = "batch-" + "a" * 64


def _planned() -> dict:
    return {
        "schema_id": "patchline.batch-run.v1",
        "run_id": RUN_ID,
        "status": "planned",
        "persisted": True,
        "revision": 0,
        "created_at_utc": "2026-11-12T00:00:00Z",
        "updated_at_utc": "2026-11-12T00:00:00Z",
        "stages": {name: "not_started" for name in ("warehouse", "dbt", "export")},
        "plan": {
            "schema_id": "patchline.batch-plan.v1",
            "run_id": RUN_ID,
            "status": "planned_only",
            "persisted": False,
            "stages": {
                name: "not_started" for name in ("warehouse", "dbt", "export")
            },
        },
    }


def _next(state: dict, action: str, stage: str, evidence: object = None) -> dict:
    proposal = propose_transition(
        state, action=action, stage=stage,
        expected_revision=state["revision"], evidence=evidence,
    )
    return preview_transition(state, proposal)


def _proof(stage: str) -> dict:
    return {"stage": stage, "sha256": "d" * 64}


def test_planned_to_warehouse_running_is_proposal_only() -> None:
    original = _planned()
    before = json.dumps(original, sort_keys=True)
    proposal = propose_transition(
        original, action="start", stage="warehouse", expected_revision=0,
    )
    assert proposal["schema_id"] == "patchline.batch-transition-proposal.v1"
    assert proposal["persisted"] is False
    assert proposal["execution_verified"] is False
    assert proposal["next_revision"] == 1
    assert proposal["next_status"] == "running"
    assert proposal["next_stages"]["warehouse"] == "running"
    assert json.dumps(original, sort_keys=True) == before


def test_preview_does_not_mark_state_persisted() -> None:
    original = _planned()
    value = _next(original, "start", "warehouse")
    assert original["persisted"] is True and original["revision"] == 0
    assert value["persisted"] is False and value["revision"] == 1
    assert value["plan"] == original["plan"]


def test_run_id_stays_unchanged() -> None:
    preview = _next(_planned(), "start", "warehouse")
    assert preview["run_id"] == RUN_ID


def test_cannot_start_dbt_without_warehouse_success() -> None:
    with pytest.raises(TransitionError, match="Previous stage"):
        _next(_planned(), "start", "dbt")


def test_cannot_start_export_without_dbt_success() -> None:
    with pytest.raises(TransitionError, match="Previous stage"):
        _next(_planned(), "start", "export")


def test_cannot_complete_unstarted_stage() -> None:
    with pytest.raises(TransitionError, match="not running"):
        _next(_planned(), "complete", "warehouse", _proof("warehouse"))


def test_cannot_fail_unstarted_stage() -> None:
    with pytest.raises(TransitionError, match="not running"):
        _next(_planned(), "fail", "warehouse", {"error_code": "INPUT_INVALID"})


def test_start_rejects_evidence() -> None:
    with pytest.raises(TransitionError, match="must not assert"):
        _next(_planned(), "start", "warehouse", _proof("warehouse"))


def test_completion_requires_stage_evidence() -> None:
    started = _next(_planned(), "start", "warehouse")
    with pytest.raises(TransitionError, match="Completion requires"):
        _next(started, "complete", "warehouse")


@pytest.mark.parametrize(
    "bad",
    [
        {"stage": "dbt", "sha256": "d" * 64},
        {"stage": "warehouse", "sha256": "BAD"},
        {"stage": "warehouse", "sha256": "d" * 64, "extra": "not allowed"},
    ],
)
def test_completion_rejects_invalid_evidence(bad: dict) -> None:
    started = _next(_planned(), "start", "warehouse")
    with pytest.raises(TransitionError, match="Completion"):
        _next(started, "complete", "warehouse", bad)


def test_completion_does_not_verify_the_digest() -> None:
    started = _next(_planned(), "start", "warehouse")
    proposal = propose_transition(
        started, action="complete", stage="warehouse", expected_revision=1,
        evidence=_proof("warehouse"),
    )
    assert proposal["execution_verified"] is False
    assert proposal["next_stages"]["warehouse"] == "succeeded"


def test_rejects_stale_revision() -> None:
    with pytest.raises(TransitionError, match="Stale"):
        propose_transition(_planned(), action="start", stage="warehouse", expected_revision=1)


def test_rejects_boolean_revision() -> None:
    with pytest.raises(TransitionError, match="Stale"):
        propose_transition(_planned(), action="start", stage="warehouse", expected_revision=True)


def test_rejects_duplicate_start() -> None:
    started = _next(_planned(), "start", "warehouse")
    with pytest.raises(TransitionError, match="already started"):
        _next(started, "start", "warehouse")


def test_rejects_parallel_stage() -> None:
    started = _next(_planned(), "start", "warehouse")
    with pytest.raises(TransitionError, match="Previous stage"):
        _next(started, "start", "dbt")


def test_three_stages_complete_only_in_order() -> None:
    state = _planned()
    for stage in ("warehouse", "dbt", "export"):
        state = _next(state, "start", stage)
        state = _next(state, "complete", stage, _proof(stage))
    assert state["revision"] == 6
    assert state["status"] == "succeeded"
    assert state["persisted"] is False
    assert all(value == "succeeded" for value in state["stages"].values())


def test_terminal_success_rejects_replay() -> None:
    state = _planned()
    for stage in ("warehouse", "dbt", "export"):
        state = _next(state, "start", stage)
        state = _next(state, "complete", stage, _proof(stage))
    with pytest.raises(TransitionError, match="Terminal"):
        _next(state, "start", "warehouse")


def test_failed_stage_is_terminal() -> None:
    started = _next(_planned(), "start", "warehouse")
    failed = _next(started, "fail", "warehouse", {"error_code": "VALIDATION_ERROR"})
    assert failed["status"] == "failed"
    assert failed["stages"]["warehouse"] == "failed"
    with pytest.raises(TransitionError, match="Terminal"):
        _next(failed, "start", "dbt")


@pytest.mark.parametrize("code", ["", "lowercase", "spaced string", "A" * 65])
def test_failure_code_is_bounded(code: str) -> None:
    started = _next(_planned(), "start", "warehouse")
    with pytest.raises(TransitionError, match="Unsafe failure"):
        _next(started, "fail", "warehouse", {"error_code": code})


def test_proposal_tamper_rejected() -> None:
    state = _planned()
    proposal = propose_transition(
        state, action="start", stage="warehouse", expected_revision=0,
    )
    proposal["next_revision"] = 99
    with pytest.raises(TransitionError, match="differs"):
        preview_transition(state, proposal)


def test_source_plan_tamper_rejected() -> None:
    state = _planned()
    state["plan"]["run_id"] = "batch-" + "b" * 64
    with pytest.raises(TransitionError, match="plan disagree"):
        _next(state, "start", "warehouse")


def test_invalid_persisted_state_rejected() -> None:
    state = _planned()
    state["stages"]["warehouse"] = "succeeded"
    with pytest.raises(TransitionError, match="Planned run"):
        _next(state, "start", "warehouse")


def test_original_is_deep_copy_unmodified() -> None:
    state = _planned()
    original = deepcopy(state)
    _next(state, "start", "warehouse")
    assert state == original


def test_unknown_action_is_rejected() -> None:
    with pytest.raises(TransitionError, match="Unknown"):
        propose_transition(_planned(), action="cancel", stage="warehouse", expected_revision=0)


def test_unknown_stage_is_rejected() -> None:
    with pytest.raises(TransitionError, match="Unknown"):
        propose_transition(_planned(), action="start", stage="network", expected_revision=0)
