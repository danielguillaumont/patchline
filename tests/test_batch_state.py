"""Offline state-reservation tests; no network, DuckDB or dbt is run."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from patchline.batch.plan import (
    ANALYTICS_CONTRACT,
    BatchPlanError,
)
from patchline.batch.plan import (
    SCHEMA_ID as PLAN_SCHEMA_ID,
)
from patchline.batch.state import BatchStateError, initialize_run, read_run
from patchline.cli import main

KEV_ID = "a" * 64
EPSS_ID = "b" * 64


@pytest.fixture
def planned_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict]:
    data = tmp_path / "data"
    data.mkdir()
    identity = {
        "schema_id": PLAN_SCHEMA_ID,
        "analytics_contract": ANALYTICS_CONTRACT,
        "kev_snapshot_id": KEV_ID,
        "epss_snapshot_id": EPSS_ID,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    run_id = "batch-" + hashlib.sha256(canonical).hexdigest()
    run_dir = data.resolve() / "runs" / run_id
    plan = {
        "schema_id": PLAN_SCHEMA_ID,
        "status": "planned_only",
        "persisted": False,
        "run_id": run_id,
        "analytics_contract": ANALYTICS_CONTRACT,
        "sources": {
            "kev": {"snapshot_id": KEV_ID, "row_count": 2},
            "epss": {"snapshot_id": EPSS_ID, "row_count": 3},
        },
        "targets": {
            "run_directory": str(run_dir),
            "warehouse": str(run_dir / "warehouse" / "patchline.duckdb"),
            "v2_export": str(run_dir / "exports" / "v2"),
        },
        "stages": {"warehouse": "not_started", "dbt": "not_started", "export": "not_started"},
    }

    def fake_plan(path: Path, *, kev_snapshot: str, epss_snapshot: str) -> dict:
        assert Path(path) == data
        assert kev_snapshot == KEV_ID
        assert epss_snapshot == EPSS_ID
        if run_dir.exists():
            raise BatchPlanError("Run workspace already exists; refusing a potential overwrite")
        return deepcopy(plan)

    monkeypatch.setattr("patchline.batch.state.plan_batch", fake_plan)
    return data, plan


def _init(pair: tuple[Path, dict]) -> dict:
    return initialize_run(pair[0], kev_snapshot=KEV_ID, epss_snapshot=EPSS_ID)


def _state_file(plan: dict) -> Path:
    return Path(plan["targets"]["run_directory"]) / "run-state.json"


def test_init_creates_only_planned_state(planned_pair: tuple[Path, dict]) -> None:
    data, plan = planned_pair
    value = _init(planned_pair)
    assert value["schema_id"] == "patchline.batch-run.v1"
    assert value["status"] == "planned" and value["persisted"] is True
    assert value["run_id"] == plan["run_id"]
    assert value["revision"] == 0
    assert set(value["stages"].values()) == {"not_started"}
    assert value["plan"] == plan
    assert not Path(plan["targets"]["warehouse"]).exists()
    assert not Path(plan["targets"]["v2_export"]).exists()
    assert [p.name for p in (data / "runs" / plan["run_id"]).iterdir()] == ["run-state.json"]
    assert read_run(data, run_id=plan["run_id"]) == value


def test_replay_rejected_without_modifying_record(planned_pair: tuple[Path, dict]) -> None:
    _, plan = planned_pair
    _init(planned_pair)
    before = _state_file(plan).read_bytes()
    with pytest.raises(BatchStateError, match="already exists"):
        _init(planned_pair)
    assert _state_file(plan).read_bytes() == before


def test_incomplete_workspace_is_not_repaired(planned_pair: tuple[Path, dict]) -> None:
    data, plan = planned_pair
    Path(plan["targets"]["run_directory"]).mkdir(parents=True)
    with pytest.raises(BatchStateError, match="already exists"):
        _init(planned_pair)
    with pytest.raises(BatchStateError, match="state file"):
        read_run(data, run_id=plan["run_id"])
    assert not _state_file(plan).exists()


def test_missing_state_is_rejected(planned_pair: tuple[Path, dict]) -> None:
    data, plan = planned_pair
    with pytest.raises(BatchStateError, match="Run directory missing"):
        read_run(data, run_id=plan["run_id"])
    assert not (data / "runs").exists()


@pytest.mark.parametrize("bad", ["", "batch-" + "A" * 64, "../x", "batch-" + "0" * 63])
def test_invalid_run_id_is_rejected(planned_pair: tuple[Path, dict], bad: str) -> None:
    data, _ = planned_pair
    with pytest.raises(BatchStateError, match="Run ID must be"):
        read_run(data, run_id=bad)


def test_corrupted_state_is_rejected(planned_pair: tuple[Path, dict]) -> None:
    data, plan = planned_pair
    _init(planned_pair)
    _state_file(plan).write_text("{broken", encoding="utf-8")
    with pytest.raises(BatchStateError, match="Unreadable run state"):
        read_run(data, run_id=plan["run_id"])


@pytest.mark.parametrize("key,value", [("status", "succeeded"), ("revision", 1)])
def test_unsupported_status_and_revision_are_rejected(
    planned_pair: tuple[Path, dict], key: str, value: object
) -> None:
    data, plan = planned_pair
    _init(planned_pair)
    path = _state_file(plan)
    record = json.loads(path.read_text(encoding="utf-8"))
    record[key] = value
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(BatchStateError):
        read_run(data, run_id=plan["run_id"])


def test_changed_snapshot_identity_is_rejected(planned_pair: tuple[Path, dict]) -> None:
    data, plan = planned_pair
    _init(planned_pair)
    path = _state_file(plan)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["plan"]["sources"]["kev"]["snapshot_id"] = "c" * 64
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(BatchStateError, match="Stored plan"):
        read_run(data, run_id=plan["run_id"])


def test_changed_target_is_rejected(planned_pair: tuple[Path, dict]) -> None:
    data, plan = planned_pair
    _init(planned_pair)
    path = _state_file(plan)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["plan"]["targets"]["warehouse"] = "somewhere-else.duckdb"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(BatchStateError, match="targets"):
        read_run(data, run_id=plan["run_id"])


def test_failure_to_plan_does_not_create_workspace(
    planned_pair: tuple[Path, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _ = planned_pair

    def reject(*_args: object, **_kwargs: object) -> dict:
        raise BatchPlanError("source digest mismatch")

    monkeypatch.setattr("patchline.batch.state.plan_batch", reject)
    with pytest.raises(BatchStateError, match="source digest mismatch"):
        _init(planned_pair)
    assert not (data / "runs").exists()


def test_cli_init_and_status(
    planned_pair: tuple[Path, dict], capsys: pytest.CaptureFixture[str]
) -> None:
    data, plan = planned_pair
    assert main([
        "batch", "init", "--data-dir", str(data),
        "--kev-snapshot", KEV_ID, "--epss-snapshot", EPSS_ID,
    ]) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == "planned"
    assert main([
        "batch", "status", "--data-dir", str(data), "--run-id", plan["run_id"],
    ]) == 0
    assert json.loads(capsys.readouterr().out) == record


def test_cli_replay_fails_nonzero(
    planned_pair: tuple[Path, dict], capsys: pytest.CaptureFixture[str]
) -> None:
    data, _ = planned_pair
    assert main([
        "batch", "init", "--data-dir", str(data),
        "--kev-snapshot", KEV_ID, "--epss-snapshot", EPSS_ID,
    ]) == 0
    capsys.readouterr()
    assert main([
        "batch", "init", "--data-dir", str(data),
        "--kev-snapshot", KEV_ID, "--epss-snapshot", EPSS_ID,
    ]) == 1
    assert "already exists" in capsys.readouterr().err
