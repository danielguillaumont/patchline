"""EA-03A4E3: integrated synthetic join -> local bundle -> independent evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from patchline.demos.cve_pipeline import (
    DEMO_ID,
    CVEPipelineDemoError,
    create_demonstration,
    main,
    verify_demonstration,
)
from patchline.exports.cve_bundle import CVEBundleError
from patchline.fixtures.cve_pipeline import synthetic_selection_and_rows
from patchline.warehouse.cross_source_join import BoundedJoinError, build_bounded_join


def _make(tmp_path: Path) -> Path:
    output = tmp_path / "demo"
    create_demonstration(output_dir=output, acknowledge_synthetic_only=True)
    return output


def test_produces_repeatable_local_artefacts(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    evidence = verify_demonstration(demo_dir=directory)
    assert evidence["schema_id"] == DEMO_ID
    assert evidence["data_kind"] == "synthetic_fixture"
    assert evidence["status"] == "verified_offline_synthetic_demonstration"
    assert evidence["byte_identical_repeats"] is True
    assert evidence["public_release_approved"] is False
    assert evidence["original_source_archives_reverified"] is False
    assert evidence["coverage"]["nvd_query_cves"] == 3
    assert evidence["coverage"]["in_selected_kev_snapshot"] == 2
    assert evidence["coverage"]["with_selected_epss_score"] == 1
    assert len(evidence["runs"]) == 2
    for name in ("bounded-join.json", "bundle/candidate.json", "bundle/manifest.json"):
        assert (directory / "run-a" / name).read_bytes() == (
            directory / "run-b" / name
        ).read_bytes()


def test_missing_epss_not_imputed_and_true_zero_preserved(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    candidate = json.loads((directory / "run-a/bundle/candidate.json").read_bytes())
    records = candidate["records"]
    assert [item["cve_id"] for item in records] == [
        "CVE-2099-0001", "CVE-2099-0003", "CVE-2099-9999",
    ]
    assert records[0]["epss"]["score"] == 0.0
    assert records[0]["epss"]["has_score_in_selected_snapshot"] is True
    assert records[1]["epss"]["score"] is None
    assert records[1]["epss"]["has_score_in_selected_snapshot"] is False
    assert [m["cvss_version"] for m in records[0]["nvd"]["cvss_metrics"]] == [
        "3.1", "4.0",
    ]
    assert records[2]["nvd"]["cvss_metrics"] == []


def test_rejects_reuse_of_output_path(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    first = (directory / "run-a/bundle/candidate.json").read_bytes()
    with pytest.raises(CVEPipelineDemoError, match="refusing overwrite"):
        create_demonstration(output_dir=directory, acknowledge_synthetic_only=True)
    assert (directory / "run-a/bundle/candidate.json").read_bytes() == first


def test_requires_explicit_opt_in_and_creates_nothing(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    with pytest.raises(CVEPipelineDemoError, match="acknowledge-synthetic-only"):
        create_demonstration(output_dir=directory, acknowledge_synthetic_only=False)
    assert not directory.exists()


def test_refuses_git_worktree(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    with pytest.raises(CVEPipelineDemoError, match="Git working tree"):
        create_demonstration(output_dir=root / "demo", acknowledge_synthetic_only=True)


def test_rejects_missing_or_extra_demo_artifacts(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    (directory / "unexpected.txt").write_text("x", encoding="utf-8")
    with pytest.raises(CVEPipelineDemoError, match="exactly two runs"):
        verify_demonstration(demo_dir=directory)
    (directory / "unexpected.txt").unlink()
    (directory / "run-a/bounded-join.json").unlink()
    with pytest.raises(CVEPipelineDemoError, match="Unexpected files"):
        verify_demonstration(demo_dir=directory)


def test_rejects_tampered_bundle_candidate(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    candidate = directory / "run-b/bundle/candidate.json"
    candidate.write_bytes(candidate.read_bytes() + b" ")
    with pytest.raises(CVEBundleError, match="byte count mismatch"):
        verify_demonstration(demo_dir=directory)


def test_rejects_tampered_source_even_if_json_is_valid(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    source = directory / "run-a/bounded-join.json"
    data = json.loads(source.read_bytes())
    data["records"][0]["epss"]["score"] = 0.25
    source.write_bytes((json.dumps(data, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    with pytest.raises(CVEPipelineDemoError, match="independently rebuilt fixture"):
        verify_demonstration(demo_dir=directory)


def test_rejects_changed_evidence_digest(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    evidence_file = directory / "evidence.json"
    evidence = json.loads(evidence_file.read_bytes())
    evidence["runs"][0]["candidate_sha256"] = "0" * 64
    evidence_file.write_bytes((json.dumps(evidence, sort_keys=True,
                                          separators=(",", ":")) + "\n").encode("utf-8"))
    with pytest.raises(CVEPipelineDemoError, match="Evidence document does not reconcile"):
        verify_demonstration(demo_dir=directory)


def test_rejects_changed_run_provenance(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    manifest = directory / "run-a/bundle/manifest.json"
    data = json.loads(manifest.read_bytes())
    data["nvd_query_id"] = "f" * 64
    manifest.write_bytes((json.dumps(data, sort_keys=True,
                                     separators=(",", ":")) + "\n").encode("utf-8"))
    with pytest.raises(CVEBundleError, match="Manifest NVD query identity"):
        verify_demonstration(demo_dir=directory)


def test_integrated_policy_rejects_future_nvd_record() -> None:
    selected, rows = synthetic_selection_and_rows()
    rows["nvd_rows"][0] = (*rows["nvd_rows"][0][:3],
                           "2026-01-16T00:00:00.000", *rows["nvd_rows"][0][4:])
    with pytest.raises(BoundedJoinError, match="modified is after"):
        build_bounded_join(selected, cutoff_date="2026-01-15",
                           acknowledge_bounded_nvd=True, **rows)


def test_integrated_policy_rejects_false_global_coverage() -> None:
    selected, rows = synthetic_selection_and_rows()
    selected = deepcopy(selected)
    selected["nvd"]["source_scope_flags"]["global_nvd_completeness_attested"] = True
    with pytest.raises(BoundedJoinError, match="global coverage"):
        build_bounded_join(selected, cutoff_date="2026-01-15",
                           acknowledge_bounded_nvd=True, **rows)


def test_cli_create_and_verify_produce_matching_json(tmp_path: Path, capsys) -> None:
    directory = tmp_path / "demo"
    assert main(["create", "--output-dir", str(directory),
                 "--acknowledge-synthetic-only"]) == 0
    created = json.loads(capsys.readouterr().out)
    assert main(["verify", "--demo-dir", str(directory)]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert created == verified
    assert created["public_release_approved"] is False


def test_cli_without_opt_in_refuses(tmp_path: Path, capsys) -> None:
    directory = tmp_path / "demo"
    assert main(["create", "--output-dir", str(directory)]) == 1
    assert "acknowledge-synthetic-only" in capsys.readouterr().err
    assert not directory.exists()


def test_verification_does_not_change_any_bytes(tmp_path: Path) -> None:
    directory = _make(tmp_path)
    contents = {str(p.relative_to(directory)): p.read_bytes()
                for p in directory.rglob("*") if p.is_file()}
    verify_demonstration(demo_dir=directory)
    after = {str(p.relative_to(directory)): p.read_bytes()
             for p in directory.rglob("*") if p.is_file()}
    assert after == contents


def test_works_with_non_ascii_parent_path(tmp_path: Path) -> None:
    parent = tmp_path / "échantillon"
    parent.mkdir()
    directory = parent / "demo"
    create_demonstration(output_dir=directory, acknowledge_synthetic_only=True)
    assert verify_demonstration(demo_dir=directory)["byte_identical_repeats"] is True
