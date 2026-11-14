"""EA-05D1 tests for a read-only offline CVE investigation report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchline.demos.cve_pipeline import create_demonstration
from patchline.demos.local_cve_explorer import (
    REPORT_ID,
    LocalCVEExplorerError,
    _embedded_json,
    create_local_report,
    main,
)
from patchline.exports.cve_bundle import REPO_ROOT, CVEBundleError


@pytest.fixture
def bundle(tmp_path: Path) -> tuple[Path, Path]:
    demo = tmp_path / "synthetic-demo"
    create_demonstration(output_dir=demo, acknowledge_synthetic_only=True)
    return demo / "run-a" / "bounded-join.json", demo / "run-a" / "bundle"


def test_creates_standalone_report_from_independently_verified_bundle(
    bundle: tuple[Path, Path], tmp_path: Path,
) -> None:
    source, directory = bundle
    output = tmp_path / "investigation.html"
    result = create_local_report(source_report=source, bundle_dir=directory,
                                 output_file=output)
    assert result["schema_id"] == REPORT_ID
    assert result["status"] == "verified_consistency_local_html_created"
    assert result["public_release_approved"] is False
    assert result["records"] == 3
    rendered = output.read_text(encoding="utf-8")
    assert "LOCAL-ONLY REPORT" in rendered
    assert "CVE INVESTIGATION / SOURCE-SCOPED" in rendered
    assert "CVE-2099-0001" in rendered
    assert "CVE-2099-0003" in rendered
    assert "CVE-2099-9999" in rendered
    assert "public_release_approved\":false" in rendered
    assert "source_join_sha256" in rendered
    assert 'connect-src \'none\'' in rendered
    assert "fetch(" not in rendered


def test_repeated_identical_inputs_make_identical_html(
    bundle: tuple[Path, Path], tmp_path: Path,
) -> None:
    source, directory = bundle
    first = tmp_path / "first.html"
    second = tmp_path / "second.html"
    a = create_local_report(source_report=source, bundle_dir=directory, output_file=first)
    b = create_local_report(source_report=source, bundle_dir=directory, output_file=second)
    assert first.read_bytes() == second.read_bytes()
    assert a["report_sha256"] == b["report_sha256"]


def test_output_never_overwritten(bundle: tuple[Path, Path], tmp_path: Path) -> None:
    source, directory = bundle
    output = tmp_path / "existing.html"
    output.write_bytes(b"private existing report")
    with pytest.raises(LocalCVEExplorerError, match="refusing overwrite"):
        create_local_report(source_report=source, bundle_dir=directory,
                            output_file=output)
    assert output.read_bytes() == b"private existing report"


def test_changed_candidate_is_rejected_before_report_created(
    bundle: tuple[Path, Path], tmp_path: Path,
) -> None:
    source, directory = bundle
    candidate = directory / "candidate.json"
    candidate.write_bytes(candidate.read_bytes() + b" ")
    output = tmp_path / "untrusted.html"
    with pytest.raises(CVEBundleError, match="byte count mismatch"):
        create_local_report(source_report=source, bundle_dir=directory,
                            output_file=output)
    assert not output.exists()


def test_refuses_output_inside_git_repository(bundle: tuple[Path, Path]) -> None:
    source, directory = bundle
    destination = REPO_ROOT / "unsafe-public-cve-export.html"
    with pytest.raises(LocalCVEExplorerError, match="source repository"):
        create_local_report(source_report=source, bundle_dir=directory,
                            output_file=destination)
    assert not destination.exists()


def test_requires_absolute_html_output(bundle: tuple[Path, Path], tmp_path: Path) -> None:
    source, directory = bundle
    with pytest.raises(LocalCVEExplorerError, match="absolute path"):
        create_local_report(source_report=source, bundle_dir=directory,
                            output_file=Path("relative.html"))
    with pytest.raises(LocalCVEExplorerError, match=".html"):
        create_local_report(source_report=source, bundle_dir=directory,
                            output_file=tmp_path / "not-html.json")


def test_embedded_data_cannot_break_script_element() -> None:
    result = _embedded_json({"title": '</script><script>alert("x")</script>&'})
    assert "</script>" not in result
    assert "<script>" not in result
    assert "<" not in result and ">" not in result and "&" not in result
    assert json.loads(result)["title"] == '</script><script>alert("x")</script>&'


def test_cli_invalid_candidate_returns_failure_without_writing(
    bundle: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    source, directory = bundle
    (directory / "manifest.json").write_bytes(b"{}")
    output = tmp_path / "must-not-create.html"
    assert main(["--source-report", str(source), "--bundle-dir", str(directory),
                 "--output", str(output)]) == 1
    assert json.loads(capsys.readouterr().err)["status"] == "failed"
    assert not output.exists()
