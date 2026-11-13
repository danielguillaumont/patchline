"""P6B2B2B append-only proposal log tests; no real archives or execution."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from patchline.batch.journal import BatchJournalError
from patchline.batch.proposal_events import (
    BatchProposalLogError,
    append_proposal_event,
    inspect_proposal_events,
)
from patchline.batch.state import BatchStateError

RUN_ID = "batch-" + "a" * 64
STAGES = ("warehouse", "dbt", "export")


def _planned() -> dict:
    return {
        "schema_id": "patchline.batch-run.v1",
        "run_id": RUN_ID,
        "status": "planned",
        "persisted": True,
        "revision": 0,
        "created_at_utc": "2026-11-12T00:00:00Z",
        "updated_at_utc": "2026-11-12T00:00:00Z",
        "stages": {name: "not_started" for name in STAGES},
        "plan": {
            "schema_id": "patchline.batch-plan.v1",
            "run_id": RUN_ID,
            "status": "planned_only",
            "persisted": False,
            "stages": {name: "not_started" for name in STAGES},
        },
    }


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Disposable planned run and genesis with fake checked storage readers."""
    from patchline.batch import proposal_events as events

    data = tmp_path / "data"
    run_dir = data / "runs" / RUN_ID
    journal = run_dir / "journal"
    journal.mkdir(parents=True)
    state_path = run_dir / "run-state.json"
    state_path.write_text(json.dumps(_planned(), sort_keys=True), encoding="utf-8")
    state_bytes = state_path.read_bytes()
    genesis_path = journal / "000000-genesis.json"
    genesis_path.write_text("anchored genesis fixture", encoding="utf-8")
    genesis_bytes = genesis_path.read_bytes()

    def read_checked(path: Path, *, run_id: str) -> dict:
        assert Path(path) == data
        if run_id != RUN_ID or state_path.read_bytes() != state_bytes:
            raise BatchStateError("Original state changed")
        return deepcopy(json.loads(state_path.read_text(encoding="utf-8")))

    def inspect_checked(path: Path, *, run_id: str) -> dict:
        assert Path(path) == data
        if run_id != RUN_ID or genesis_path.read_bytes() != genesis_bytes:
            raise BatchJournalError("Genesis changed")
        return {
            "status": "verified_genesis_only",
            "run_id": RUN_ID,
            "revision": 0,
            "entry_sha256": hashlib.sha256(genesis_bytes).hexdigest(),
        }

    monkeypatch.setattr(events, "read_run", read_checked)
    monkeypatch.setattr(events, "inspect_journal", inspect_checked)
    monkeypatch.setattr(events, "_workspace", lambda _data, _id: (data / "runs", run_dir))
    return data, run_dir


def _append(data: Path, action: str, stage: str, rev: int, evidence: object = None) -> dict:
    return append_proposal_event(
        data, run_id=RUN_ID, action=action, stage=stage,
        expected_revision=rev, evidence=evidence,
    )


def _entry(run_dir: Path, sequence: int) -> Path:
    return run_dir / "proposal-events" / f"{sequence:06d}-proposal.json"


def _proof(stage: str) -> dict:
    return {"stage": stage, "sha256": "d" * 64}


def _rewrite_entry(run_dir: Path, sequence: int, change) -> None:
    path = _entry(run_dir, sequence)
    obj = json.loads(path.read_text(encoding="utf-8"))
    change(obj)
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_empty_log_reports_only_original_state(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    result = inspect_proposal_events(data, run_id=RUN_ID)
    assert result["status"] == "verified_proposals_only"
    assert result["entries"] == 0 and result["preview_revision"] == 0
    assert result["original_run_status"] == "planned"
    assert not (run_dir / "proposal-events").exists()


def test_first_event_is_proposal_only(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    state_before = (run_dir / "run-state.json").read_bytes()
    genesis_before = (run_dir / "journal" / "000000-genesis.json").read_bytes()
    event = _append(data, "start", "warehouse", 0)
    assert event["status"] == "appended_proposal_only"
    assert event["sequence"] == 1 and event["preview_revision"] == 1
    assert event["execution_verified"] is False
    assert event["persisted_run_progress"] is False
    assert _entry(run_dir, 1).exists()
    assert (run_dir / "run-state.json").read_bytes() == state_before
    assert (run_dir / "journal" / "000000-genesis.json").read_bytes() == genesis_before


def test_first_entry_anchor_matches_genesis(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    before = inspect_proposal_events(data, run_id=RUN_ID)
    _append(data, "start", "warehouse", 0)
    entry = json.loads(_entry(run_dir, 1).read_text(encoding="utf-8"))
    assert entry["previous_entry_sha256"] == before["last_entry_sha256"]
    assert inspect_proposal_events(data, run_id=RUN_ID)["entries"] == 1


def test_sequential_proposals_have_linked_hashes(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    first = _append(data, "start", "warehouse", 0)
    second = _append(data, "complete", "warehouse", 1, _proof("warehouse"))
    assert second["sequence"] == 2
    record = json.loads(_entry(run_dir, 2).read_text(encoding="utf-8"))
    assert record["previous_entry_sha256"] == first["entry_sha256"]
    result = inspect_proposal_events(data, run_id=RUN_ID)
    assert result["entries"] == 2 and result["preview_revision"] == 2
    assert result["original_run_revision"] == 0
    assert result["execution_verified"] is False


def test_full_hypothetical_six_events_never_claim_execution(store: tuple[Path, Path]) -> None:
    data, _ = store
    revision = 0
    for stage in STAGES:
        _append(data, "start", stage, revision)
        revision += 1
        _append(data, "complete", stage, revision, _proof(stage))
        revision += 1
    result = inspect_proposal_events(data, run_id=RUN_ID)
    assert result["entries"] == 6
    assert result["preview_revision"] == 6
    assert result["original_run_status"] == "planned"
    assert result["execution_verified"] is False


def test_seventh_event_rejected(store: tuple[Path, Path]) -> None:
    data, _ = store
    for i, stage in enumerate(STAGES):
        _append(data, "start", stage, 2 * i)
        _append(data, "complete", stage, 2 * i + 1, _proof(stage))
    with pytest.raises(BatchProposalLogError, match="at its limit"):
        _append(data, "start", "warehouse", 6)


def test_duplicate_start_rejected_without_overwrite(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    before = _entry(run_dir, 1).read_bytes()
    with pytest.raises(BatchProposalLogError, match="Invalid proposed transition"):
        _append(data, "start", "warehouse", 1)
    assert _entry(run_dir, 1).read_bytes() == before
    assert not _entry(run_dir, 2).exists()


def test_stale_revision_fails_closed(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    with pytest.raises(BatchProposalLogError, match="Stale"):
        _append(data, "complete", "warehouse", 0, _proof("warehouse"))
    assert not _entry(run_dir, 2).exists()


def test_dbt_cannot_start_before_warehouse(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    with pytest.raises(BatchProposalLogError, match="Previous stage"):
        _append(data, "start", "dbt", 0)
    assert not (run_dir / "proposal-events").exists()


def test_complete_requires_metadata_even_for_hypothesis(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    with pytest.raises(BatchProposalLogError, match="Completion requires"):
        _append(data, "complete", "warehouse", 1)
    assert not _entry(run_dir, 2).exists()


def test_failure_proposal_is_terminal(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    _append(data, "fail", "warehouse", 1, {"error_code": "INVALID_SOURCE"})
    with pytest.raises(BatchProposalLogError, match="Terminal"):
        _append(data, "start", "dbt", 2)
    assert len(list((run_dir / "proposal-events").iterdir())) == 2


def test_tampered_metadata_rejected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    _rewrite_entry(run_dir, 1, lambda obj: obj.update({"sequence": 2}))
    with pytest.raises(BatchProposalLogError, match="integrity mismatch"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_changed_proposal_with_new_hash_still_rejected(store: tuple[Path, Path]) -> None:
    from patchline.batch import proposal_events as events

    data, run_dir = store
    _append(data, "start", "warehouse", 0)

    def tamper(record: dict) -> None:
        record["proposal"]["next_revision"] = 500
        body = {key: value for key, value in record.items() if key != "entry_sha256"}
        record["entry_sha256"] = events._sha256(events._canonical(body))

    _rewrite_entry(run_dir, 1, tamper)
    with pytest.raises(BatchProposalLogError, match="Invalid proposed transition sequence"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_previous_hash_change_rejected(store: tuple[Path, Path]) -> None:
    from patchline.batch import proposal_events as events

    data, run_dir = store
    _append(data, "start", "warehouse", 0)

    def tamper(record: dict) -> None:
        record["previous_entry_sha256"] = "a" * 64
        body = {key: value for key, value in record.items() if key != "entry_sha256"}
        record["entry_sha256"] = events._sha256(events._canonical(body))

    _rewrite_entry(run_dir, 1, tamper)
    with pytest.raises(BatchProposalLogError, match="integrity mismatch"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_missing_sequence_detected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    _append(data, "complete", "warehouse", 1, _proof("warehouse"))
    _entry(run_dir, 1).unlink()
    with pytest.raises(BatchProposalLogError, match="out-of-order"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_unexpected_extra_file_rejected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    (run_dir / "proposal-events" / "extra.txt").write_text("junk", encoding="utf-8")
    with pytest.raises(BatchProposalLogError, match="out-of-order"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_incomplete_empty_directory_refused(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    (run_dir / "proposal-events").mkdir()
    with pytest.raises(BatchProposalLogError, match="Incomplete"):
        inspect_proposal_events(data, run_id=RUN_ID)
    with pytest.raises(BatchProposalLogError, match="Incomplete"):
        _append(data, "start", "warehouse", 0)


def test_invalid_json_rejected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    _entry(run_dir, 1).write_text("{", encoding="utf-8")
    with pytest.raises(BatchProposalLogError, match="Unreadable"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_oversized_entry_rejected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    _entry(run_dir, 1).write_bytes(b"x" * (32 * 1024 + 1))
    with pytest.raises(BatchProposalLogError, match="size"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_false_execution_claim_rejected_even_with_updated_hash(
    store: tuple[Path, Path],
) -> None:
    from patchline.batch import proposal_events as events

    data, run_dir = store
    _append(data, "start", "warehouse", 0)

    def tamper(record: dict) -> None:
        record["proposal"]["execution_verified"] = True
        body = {key: value for key, value in record.items() if key != "entry_sha256"}
        record["entry_sha256"] = events._sha256(events._canonical(body))

    _rewrite_entry(run_dir, 1, tamper)
    with pytest.raises(BatchProposalLogError, match="incorrectly claims"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_changed_original_state_rejected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    (run_dir / "run-state.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(BatchProposalLogError, match="Original state"):
        inspect_proposal_events(data, run_id=RUN_ID)


def test_changed_genesis_rejected(store: tuple[Path, Path]) -> None:
    data, run_dir = store
    _append(data, "start", "warehouse", 0)
    (run_dir / "journal" / "000000-genesis.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(BatchProposalLogError, match="genesis"):
        inspect_proposal_events(data, run_id=RUN_ID)
