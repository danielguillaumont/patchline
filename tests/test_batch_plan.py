"""Offline contract tests for source-pinned, read-only batch plans."""

import gzip
import json
from pathlib import Path

import pytest

from patchline.batch.plan import BatchPlanError, plan_batch
from patchline.cli import main
from patchline.ingest.epss import ingest_epss
from patchline.ingest.kev import ingest_kev


@pytest.fixture
def archive_pair(tmp_path: Path, catalog: dict, schema: dict) -> tuple[Path, str, str]:
    data = tmp_path / "data"
    kev = ingest_kev(
        data,
        catalog_bytes=json.dumps(catalog).encode("utf-8"),
        schema_bytes=json.dumps(schema).encode("utf-8"),
    )
    epss_text = (
        "#model_version:v2026.06.15,score_date:2026-11-10T12:00:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2025-0001,0.7,0.98\n"
        "CVE-2025-0002,0.01,0.4\n"
        "CVE-2026-9999,0.3,0.7\n"
    )
    epss = ingest_epss(data, compressed_bytes=gzip.compress(epss_text.encode(), mtime=0))
    return data, kev["snapshot_id"], epss["snapshot_id"]


def _plan(pair: tuple[Path, str, str]) -> dict[str, object]:
    data, kev, epss = pair
    return plan_batch(data, kev_snapshot=kev, epss_snapshot=epss)


def test_plan_revalidates_archives_and_is_read_only(archive_pair: tuple[Path, str, str]) -> None:
    data, kev_id, epss_id = archive_pair
    before = sorted(p.relative_to(data).as_posix() for p in data.rglob("*"))
    plan = _plan(archive_pair)
    after = sorted(p.relative_to(data).as_posix() for p in data.rglob("*"))
    assert before == after
    assert plan["schema_id"] == "patchline.batch-plan.v1"
    assert plan["status"] == "planned_only"
    assert plan["persisted"] is False
    assert plan["analytics_contract"] == "patchline.analytics-export.v2"
    assert plan["sources"]["kev"]["snapshot_id"] == kev_id
    assert plan["sources"]["epss"]["snapshot_id"] == epss_id
    assert plan["sources"]["kev"]["row_count"] == 2
    assert plan["sources"]["epss"]["row_count"] == 3
    assert set(plan["stages"].values()) == {"not_started"}
    assert not (data / "runs").exists()


def test_run_id_is_stable_across_calls(archive_pair: tuple[Path, str, str]) -> None:
    first = _plan(archive_pair)
    second = _plan(archive_pair)
    assert first == second
    assert first["run_id"].startswith("batch-")
    assert len(first["run_id"]) == 70
    assert first["targets"]["run_directory"].endswith(first["run_id"])
    assert first["targets"]["warehouse"].endswith("patchline.duckdb")


def test_run_id_differs_for_other_source_pair(archive_pair: tuple[Path, str, str]) -> None:
    data, kev, epss = archive_pair
    text = (
        "#model_version:v2026.06.15,score_date:2026-11-11T12:00:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2025-0001,0.7,0.98\n"
    )
    other = ingest_epss(data, compressed_bytes=gzip.compress(text.encode(), mtime=0))
    original = plan_batch(data, kev_snapshot=kev, epss_snapshot=epss)
    alternate = plan_batch(data, kev_snapshot=kev, epss_snapshot=other["snapshot_id"])
    assert original["run_id"] != alternate["run_id"]


@pytest.mark.parametrize("bad", ["", "A" * 64, "x" * 64, "../" + "a" * 64])
def test_invalid_snapshot_ids_are_rejected(
    archive_pair: tuple[Path, str, str], bad: str
) -> None:
    data, _, epss = archive_pair
    with pytest.raises(BatchPlanError, match="lowercase 64-character"):
        plan_batch(data, kev_snapshot=bad, epss_snapshot=epss)


def test_missing_archive_is_rejected(archive_pair: tuple[Path, str, str]) -> None:
    data, kev, _ = archive_pair
    with pytest.raises(BatchPlanError, match="validation failed"):
        plan_batch(data, kev_snapshot=kev, epss_snapshot="0" * 64)


def test_archive_hash_mismatch_fails_closed(archive_pair: tuple[Path, str, str]) -> None:
    data, kev, epss = archive_pair
    catalog = data / "raw" / "kev" / kev / "catalog.json"
    catalog.write_text("{}", encoding="utf-8")
    with pytest.raises(BatchPlanError, match="SHA-256 mismatch"):
        plan_batch(data, kev_snapshot=kev, epss_snapshot=epss)
    assert not (data / "runs").exists()


def test_existing_workspace_is_not_reused(archive_pair: tuple[Path, str, str]) -> None:
    data, _, _ = archive_pair
    plan = _plan(archive_pair)
    Path(plan["targets"]["run_directory"]).mkdir(parents=True)
    with pytest.raises(BatchPlanError, match="already exists"):
        _plan(archive_pair)


def test_non_directory_workspace_root_is_rejected(
    archive_pair: tuple[Path, str, str],
) -> None:
    data, _, _ = archive_pair
    (data / "runs").write_text("not a directory", encoding="utf-8")
    with pytest.raises(BatchPlanError, match="not a normal directory"):
        _plan(archive_pair)


def test_cli_plan_prints_json_without_writing(
    archive_pair: tuple[Path, str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    data, kev, epss = archive_pair
    assert main([
        "batch", "plan", "--data-dir", str(data),
        "--kev-snapshot", kev, "--epss-snapshot", epss,
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "planned_only"
    assert not (data / "runs").exists()


def test_cli_plan_fails_nonzero_for_missing_pair(
    archive_pair: tuple[Path, str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    data, kev, _ = archive_pair
    assert main([
        "batch", "plan", "--data-dir", str(data),
        "--kev-snapshot", kev, "--epss-snapshot", "0" * 64,
    ]) == 1
    assert "Batch plan failed:" in capsys.readouterr().err
