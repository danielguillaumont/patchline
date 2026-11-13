"""EA-03A4E2: synthetic write-once bundle and independent verifier tests."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from patchline.exports.cve_bundle import (
    BUNDLE_ID,
    CANDIDATE_FILE,
    MANIFEST_FILE,
    CVEBundleError,
    create_bundle,
    main,
    verify_bundle,
)
from patchline.exports.cve_contract import JOIN_ID


def source_report() -> dict:
    """Invented source-scoped fixture; never a real vulnerability observation."""
    query = "a" * 64
    records = [
        {
            "cve_id": "CVE-2099-0001",
            "nvd": {
                "query_id": query, "vuln_status": "Analyzed",
                "published_source_timestamp": "2026-01-10T00:00:00.000",
                "modified_source_timestamp": "2026-01-11T00:00:00.000",
                "source_page_sha256": "d" * 64,
                "cvss_metrics": [{
                    "metric_index": 0, "metric_key": "cvssMetricV31",
                    "cvss_version": "3.1", "metric_source": "synthetic",
                    "metric_type": "Primary", "vector_string": None,
                    "base_score": 9.8, "base_severity": "CRITICAL",
                }],
            },
            "kev": {"listed_in_selected_snapshot": True, "date_added": "2026-01-11"},
            "epss": {"has_score_in_selected_snapshot": True, "score": 0.0, "percentile": 0.0},
        },
        {
            "cve_id": "CVE-2099-0002",
            "nvd": {
                "query_id": query, "vuln_status": "Awaiting Analysis",
                "published_source_timestamp": "2026-01-10T00:00:00.000",
                "modified_source_timestamp": "2026-01-12T00:00:00.000",
                "source_page_sha256": "d" * 64, "cvss_metrics": [],
            },
            "kev": {"listed_in_selected_snapshot": False, "date_added": None},
            "epss": {"has_score_in_selected_snapshot": False, "score": None, "percentile": None},
        },
    ]
    return {
        "schema_id": JOIN_ID,
        "status": "local_bounded_nvd_cve_join_executed",
        "cross_source_join_executed": True,
        "data_kind": "source_scoped_local_analysis",
        "row_scope": "only_cves_returned_by_one_bounded_nvd_query",
        "analysis_cutoff_date": "2026-01-15",
        "time_precision": "calendar_date_guard_only_not_as_of_reconstruction",
        "selection_contract": "exploit-atlas.cross-source-selection.v1",
        "time_coverage_contract": "exploit-atlas.time-coverage-preflight.v1",
        "source_ids": {
            "nvd_query_id": query,
            "nvd_query_mode": "last_modified_window",
            "kev_snapshot_id": "b" * 64,
            "kev_source_date": "2026-01-11",
            "epss_snapshot_id": "c" * 64,
            "epss_score_date": "2026-01-12",
            "epss_model_version": "v-ci-synthetic",
        },
        "coverage": {
            "nvd_query_cves": 2,
            "in_selected_kev_snapshot": 1,
            "with_selected_epss_score": 1,
            "nvd_cvss_metric_rows": 1,
            "missing_nvd_cves_outside_query_are_unknown": True,
        },
        "records": records,
        "historical_as_of_reconstruction_attested": False,
        "nvd_global_coverage_attested": False,
        "organization_asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
        "published_to_public_demo": False,
    }


def _save_source(tmp_path: Path, source: dict | None = None) -> Path:
    file = tmp_path / "original-bounded-join.json"
    file.write_text(json.dumps(source if source is not None else source_report()), encoding="utf-8")
    return file


def _make(tmp_path: Path) -> tuple[Path, Path]:
    source = _save_source(tmp_path)
    bundle = tmp_path / "local-consumer-bundle"
    result = create_bundle(
        source_report=source, output_dir=bundle, acknowledge_local_only=True,
    )
    assert result["status"] == "verified_local_bundle_not_published"
    return source, bundle


def _write_canonical(file: Path, doc: dict) -> None:
    payload = (json.dumps(doc, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False) + "\n").encode("utf-8")
    file.write_bytes(payload)


def _update_manifest_checksum(bundle: Path) -> None:
    raw = (bundle / CANDIDATE_FILE).read_bytes()
    manifest = json.loads((bundle / MANIFEST_FILE).read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    manifest["files"][0]["bytes"] = len(raw)
    _write_canonical(bundle / MANIFEST_FILE, manifest)


def test_round_trip_local_only_and_explicit_absence(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    result = verify_bundle(source_report=source, bundle_dir=bundle)
    assert result["schema_id"] == BUNDLE_ID
    assert result["records_checked"] == 2
    assert result["public_release_approved"] is False
    records = json.loads((bundle / CANDIDATE_FILE).read_text())["records"]
    assert records[0]["epss"]["score"] == 0.0
    assert records[1]["epss"]["score"] is None
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    assert manifest["public_release_approved"] is False
    assert manifest["coverage"]["missing_nvd_cves_outside_query_are_unknown"] is True


def test_deterministic_files_for_identical_source(tmp_path: Path) -> None:
    source = _save_source(tmp_path)
    bundles = [tmp_path / "a", tmp_path / "b"]
    for output in bundles:
        create_bundle(source_report=source, output_dir=output, acknowledge_local_only=True)
    for filename in (CANDIDATE_FILE, MANIFEST_FILE):
        assert (bundles[0] / filename).read_bytes() == (bundles[1] / filename).read_bytes()


def test_requires_explicit_opt_in(tmp_path: Path) -> None:
    source = _save_source(tmp_path)
    with pytest.raises(CVEBundleError, match="acknowledgement"):
        create_bundle(source_report=source, output_dir=tmp_path / "out",
                      acknowledge_local_only=False)
    assert not (tmp_path / "out").exists()


def test_no_overwrite_even_with_identical_inputs(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    with pytest.raises(CVEBundleError, match="already exists"):
        create_bundle(source_report=source, output_dir=bundle, acknowledge_local_only=True)


def test_reject_changed_candidate_bytes(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    candidate = bundle / CANDIDATE_FILE
    candidate.write_bytes(candidate.read_bytes() + b" ")
    with pytest.raises(CVEBundleError, match="byte count mismatch"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_changed_candidate_even_when_checksum_refreshed(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    candidate = bundle / CANDIDATE_FILE
    changed = json.loads(candidate.read_text(encoding="utf-8"))
    changed["records"][0]["epss"]["score"] = 0.5
    _write_canonical(candidate, changed)
    _update_manifest_checksum(bundle)
    with pytest.raises(CVEBundleError, match="reconciliation failed"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_missing_epss_imputed_as_zero_with_new_checksum(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    candidate = bundle / CANDIDATE_FILE
    changed = json.loads(candidate.read_text(encoding="utf-8"))
    changed["records"][1]["epss"]["score"] = 0.0
    _write_canonical(candidate, changed)
    _update_manifest_checksum(bundle)
    with pytest.raises(CVEBundleError, match="reconciliation failed"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_changed_source_report(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    src = json.loads(source.read_text())
    src["source_ids"]["kev_source_date"] = "2026-01-10"
    source.write_text(json.dumps(src), encoding="utf-8")
    with pytest.raises(CVEBundleError, match="Original bounded join SHA-256 mismatch"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_modified_manifest_digest(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    manifest["files"][0]["sha256"] = "f" * 64
    _write_canonical(bundle / MANIFEST_FILE, manifest)
    with pytest.raises(CVEBundleError, match="Candidate SHA-256 mismatch"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_false_publication_claim(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    manifest["public_release_approved"] = True
    _write_canonical(bundle / MANIFEST_FILE, manifest)
    with pytest.raises(CVEBundleError, match="Public release claim forbidden"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_manifest_coverage_mismatch(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    manifest["coverage"]["nvd_query_cves"] = 999
    _write_canonical(bundle / MANIFEST_FILE, manifest)
    with pytest.raises(CVEBundleError, match="Manifest coverage differs"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_extra_file(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    (bundle / "unverified.json").write_text("{}", encoding="utf-8")
    with pytest.raises(CVEBundleError, match="missing or unexpected files"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_missing_manifest(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    (bundle / MANIFEST_FILE).unlink()
    with pytest.raises(CVEBundleError, match="missing or unexpected files"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_duplicate_json_keys_in_manifest(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    manifest = (bundle / MANIFEST_FILE)
    raw = manifest.read_text(encoding="utf-8")
    manifest.write_text(raw.replace('"schema_id":', '"schema_id":"bogus","schema_id":'),
                        encoding="utf-8")
    with pytest.raises(CVEBundleError, match="Duplicate JSON object key"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_noncanonical_manifest(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    manifest = (bundle / MANIFEST_FILE)
    manifest.write_bytes(manifest.read_bytes() + b" ")
    with pytest.raises(CVEBundleError, match="Manifest bytes are not deterministic"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_symlinked_candidate(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    candidate = bundle / CANDIDATE_FILE
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(candidate.read_bytes())
    candidate.unlink()
    try:
        candidate.symlink_to(duplicate)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable for this Windows account")
    with pytest.raises(CVEBundleError, match="symlinked file"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_tampered_cvss_metric_with_new_checksum(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    candidate = bundle / CANDIDATE_FILE
    changed = json.loads(candidate.read_text())
    changed["records"][0]["nvd"]["cvss_metrics"][0]["base_score"] = 7.0
    _write_canonical(candidate, changed)
    _update_manifest_checksum(bundle)
    with pytest.raises(CVEBundleError, match="reconciliation failed"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_changed_query_identity_with_new_checksum(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    candidate = bundle / CANDIDATE_FILE
    changed = json.loads(candidate.read_text())
    changed["source_ids"]["nvd_query_id"] = "e" * 64
    _write_canonical(candidate, changed)
    _update_manifest_checksum(bundle)
    with pytest.raises(CVEBundleError, match="reconciliation failed"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_forged_manifest_row_count(tmp_path: Path) -> None:
    source, bundle = _make(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    manifest["row_count"] = 3
    _write_canonical(bundle / MANIFEST_FILE, manifest)
    with pytest.raises(CVEBundleError, match="Manifest record count differs"):
        verify_bundle(source_report=source, bundle_dir=bundle)


def test_reject_invalid_original_join_before_writing(tmp_path: Path) -> None:
    bad = deepcopy(source_report())
    bad["records"][1]["epss"]["score"] = 0.0
    source = _save_source(tmp_path, bad)
    output = tmp_path / "must-not-exist"
    with pytest.raises(CVEBundleError, match="Consumer candidate rejected"):
        create_bundle(source_report=source, output_dir=output, acknowledge_local_only=True)
    assert not output.exists()


def test_empty_bounded_query_is_safe(tmp_path: Path) -> None:
    source = source_report()
    source["records"] = []
    source["coverage"] = {
        "nvd_query_cves": 0, "in_selected_kev_snapshot": 0,
        "with_selected_epss_score": 0, "nvd_cvss_metric_rows": 0,
        "missing_nvd_cves_outside_query_are_unknown": True,
    }
    origin = _save_source(tmp_path, source)
    bundle = tmp_path / "empty"
    result = create_bundle(source_report=origin, output_dir=bundle,
                           acknowledge_local_only=True)
    assert result["records_checked"] == 0


def test_cli_local_create_then_read_only_verify(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    source = _save_source(tmp_path)
    bundle = tmp_path / "cli-bundle"
    assert main(["create", "--source-report", str(source), "--output-dir", str(bundle),
                 "--acknowledge-local-only"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["public_release_approved"] is False
    assert main(["verify", "--source-report", str(source), "--bundle-dir", str(bundle)]) == 0
    assert json.loads(capsys.readouterr().out)["records_checked"] == 2


def test_cli_refuses_missing_opt_in(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    source = _save_source(tmp_path)
    bundle = tmp_path / "refused"
    assert main(["create", "--source-report", str(source), "--output-dir", str(bundle)]) == 1
    assert "acknowledgement required" in capsys.readouterr().err
    assert not bundle.exists()


def test_does_not_rewrite_external_source_report(tmp_path: Path) -> None:
    source = _save_source(tmp_path)
    original = source.read_bytes()
    create_bundle(source_report=source, output_dir=tmp_path / "bundle",
                  acknowledge_local_only=True)
    assert source.read_bytes() == original


def test_canonical_test_helper_writes_lf_on_every_platform(tmp_path: Path) -> None:
    path = tmp_path / "canonical.json"
    _write_canonical(path, {"value": 1})
    assert path.read_bytes() == b'{"value":1}\n'
