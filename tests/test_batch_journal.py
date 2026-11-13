"""Offline journal genesis tests: no stage execution or existing-state rewrites."""

import hashlib
import json
from pathlib import Path

import pytest

from patchline.batch.journal import BatchJournalError, initialize_journal, inspect_journal
from patchline.cli import main

KEV_ID = "a" * 64
EPSS_ID = "b" * 64


def _run_id() -> str:
    identity = {
        "schema_id": "patchline.batch-plan.v1",
        "analytics_contract": "patchline.analytics-export.v2",
        "kev_snapshot_id": KEV_ID,
        "epss_snapshot_id": EPSS_ID,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "batch-" + hashlib.sha256(canonical).hexdigest()


@pytest.fixture
def existing_run(tmp_path: Path) -> tuple[Path, str, Path, Path]:
    """A genuine P6B2A-compatible planned record, without raw feed downloads."""
    data = tmp_path / "data"
    run_id = _run_id()
    run_dir = data.resolve() / "runs" / run_id
    run_dir.mkdir(parents=True)
    stages = {name: "not_started" for name in ("warehouse", "dbt", "export")}
    plan = {
        "schema_id": "patchline.batch-plan.v1",
        "analytics_contract": "patchline.analytics-export.v2",
        "status": "planned_only",
        "persisted": False,
        "run_id": run_id,
        "stages": stages,
        "sources": {
            "kev": {"snapshot_id": KEV_ID, "source_date": "2026-11-10", "row_count": 2},
            "epss": {"snapshot_id": EPSS_ID, "source_date": "2026-11-11", "row_count": 3},
        },
        "targets": {
            "run_directory": str(run_dir),
            "warehouse": str(run_dir / "warehouse" / "patchline.duckdb"),
            "v2_export": str(run_dir / "exports" / "v2"),
        },
    }
    state = {
        "schema_id": "patchline.batch-run.v1",
        "run_id": run_id,
        "status": "planned",
        "persisted": True,
        "revision": 0,
        "created_at_utc": "2026-11-12T00:00:00Z",
        "updated_at_utc": "2026-11-12T00:00:00Z",
        "stages": stages,
        "plan": plan,
    }
    state_file = run_dir / "run-state.json"
    state_file.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data, run_id, state_file, run_dir / "journal"


def _start(run: tuple[Path, str, Path, Path]) -> dict:
    return initialize_journal(run[0], run_id=run[1])


def _status(run: tuple[Path, str, Path, Path]) -> dict:
    return inspect_journal(run[0], run_id=run[1])


def test_init_creates_one_genesis_and_preserves_original_state(existing_run) -> None:
    _, run_id, state_path, journal = existing_run
    before = state_path.read_bytes()
    result = _start(existing_run)
    assert result["run_id"] == run_id
    assert result["status"] == "initialized_genesis_only"
    assert result["revision"] == 0
    assert result["execution_verified"] is False
    assert state_path.read_bytes() == before
    assert [p.name for p in journal.iterdir()] == ["000000-genesis.json"]
    assert _status(existing_run)["entries"] == 1


def test_verified_genesis_pins_original_bytes(existing_run) -> None:
    _, _, state_file, _ = existing_run
    _start(existing_run)
    result = _status(existing_run)
    assert result["status"] == "verified_genesis_only"
    assert result["revision"] == 0
    assert result["execution_verified"] is False
    expected_hash = hashlib.sha256(state_file.read_bytes()).hexdigest()
    entry = json.loads(Path(result["journal_file"]).read_text(encoding="utf-8"))
    assert entry["source_state_sha256"] == expected_hash


def test_identical_second_init_is_rejected_without_overwrite(existing_run) -> None:
    _, _, state_file, journal = existing_run
    _start(existing_run)
    original_genesis = (journal / "000000-genesis.json").read_bytes()
    original_state = state_file.read_bytes()
    with pytest.raises(BatchJournalError, match="already exists"):
        _start(existing_run)
    assert (journal / "000000-genesis.json").read_bytes() == original_genesis
    assert state_file.read_bytes() == original_state


def test_missing_run_is_rejected_without_creating_anything(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    with pytest.raises(BatchJournalError, match="Invalid existing planned run"):
        initialize_journal(data, run_id=_run_id())
    assert not (data / "runs").exists()


@pytest.mark.parametrize("run_id", ["", "../escape", "batch-" + "Z" * 64])
def test_invalid_id_is_rejected(existing_run, run_id: str) -> None:
    with pytest.raises(BatchJournalError, match="Invalid existing planned run"):
        initialize_journal(existing_run[0], run_id=run_id)


def test_changed_original_state_bytes_are_detected(existing_run) -> None:
    _, _, state_file, _ = existing_run
    _start(existing_run)
    state_file.write_bytes(state_file.read_bytes() + b"\n")
    with pytest.raises(BatchJournalError, match="integrity mismatch"):
        _status(existing_run)


def test_tampered_genesis_digest_is_rejected(existing_run) -> None:
    _, _, _, journal = existing_run
    _start(existing_run)
    path = journal / "000000-genesis.json"
    contents = json.loads(path.read_text(encoding="utf-8"))
    contents["entry_sha256"] = "f" * 64
    path.write_text(json.dumps(contents), encoding="utf-8")
    with pytest.raises(BatchJournalError, match="integrity mismatch"):
        _status(existing_run)


def test_tampered_genesis_run_id_is_rejected(existing_run) -> None:
    _, _, _, journal = existing_run
    _start(existing_run)
    path = journal / "000000-genesis.json"
    contents = json.loads(path.read_text(encoding="utf-8"))
    contents["run_id"] = "batch-" + "e" * 64
    path.write_text(json.dumps(contents), encoding="utf-8")
    with pytest.raises(BatchJournalError, match="contract mismatch"):
        _status(existing_run)


def test_unreadable_genesis_is_rejected(existing_run) -> None:
    _, _, _, journal = existing_run
    _start(existing_run)
    (journal / "000000-genesis.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(BatchJournalError, match="Unreadable journal genesis"):
        _status(existing_run)


def test_unexpected_extra_journal_file_is_rejected(existing_run) -> None:
    _, _, _, journal = existing_run
    _start(existing_run)
    (journal / "000001-transition.json").write_text("{}", encoding="utf-8")
    with pytest.raises(BatchJournalError, match="unexpected journal"):
        _status(existing_run)


def test_incomplete_directory_is_not_repaired(existing_run) -> None:
    _, _, _, journal = existing_run
    journal.mkdir()
    with pytest.raises(BatchJournalError, match="already exists"):
        _start(existing_run)
    with pytest.raises(BatchJournalError, match="unexpected journal"):
        _status(existing_run)
    assert list(journal.iterdir()) == []


def test_unexpected_genesis_field_is_rejected(existing_run) -> None:
    _, _, _, journal = existing_run
    _start(existing_run)
    path = journal / "000000-genesis.json"
    contents = json.loads(path.read_text(encoding="utf-8"))
    contents["extra"] = "untrusted"
    path.write_text(json.dumps(contents), encoding="utf-8")
    with pytest.raises(BatchJournalError, match="structure"):
        _status(existing_run)


def test_genesis_does_not_create_pipeline_outputs(existing_run) -> None:
    _, _, _, journal = existing_run
    _start(existing_run)
    run_dir = journal.parent
    assert not (run_dir / "warehouse").exists()
    assert not (run_dir / "exports").exists()
    assert len(list(run_dir.iterdir())) == 2


def test_cli_init_then_status_on_existing_planned_run(existing_run, capsys) -> None:
    data, run_id, _, _ = existing_run
    assert main(["batch", "journal-init", "--data-dir", str(data), "--run-id", run_id]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "initialized_genesis_only"
    assert main(["batch", "journal-status", "--data-dir", str(data), "--run-id", run_id]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["status"] == "verified_genesis_only"
    assert inspected["entry_sha256"] == created["entry_sha256"]


def test_cli_replay_exits_nonzero(existing_run, capsys) -> None:
    data, run_id, _, _ = existing_run
    assert main(["batch", "journal-init", "--data-dir", str(data), "--run-id", run_id]) == 0
    capsys.readouterr()
    assert main(["batch", "journal-init", "--data-dir", str(data), "--run-id", run_id]) == 1
    assert "already exists" in capsys.readouterr().err


def test_missing_genesis_folder_does_not_get_created_by_status(existing_run) -> None:
    _, _, _, journal = existing_run
    with pytest.raises(BatchJournalError, match="Missing or unsafe journal"):
        _status(existing_run)
    assert not journal.exists()
