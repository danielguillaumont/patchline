"""EA-03A1: deterministic offline NVD response-page validation and archival."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from patchline.ingest.nvd import NVDIngestionError, archive_nvd_page, main, validate_nvd_page


def example_page() -> dict:
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-11-13T13:00:00.000",
        "resultsPerPage": 2,
        "startIndex": 0,
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "sourceIdentifier": "example.invalid",
                    "published": "2026-11-01T00:00:00.000",
                    "lastModified": "2026-11-12T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Invented test description."}],
                    "metrics": {"cvssMetricV31": []},
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-54321",
                    "published": "2026-11-02T00:00:00.000",
                    "lastModified": "2026-11-13T00:00:00.000",
                    "vulnStatus": "Awaiting Analysis",
                    "descriptions": [],
                    "weaknesses": [],
                }
            },
        ],
    }


def encoded(record: dict) -> bytes:
    return json.dumps(record, ensure_ascii=False).encode("utf-8")


def test_valid_page_reports_actual_scope_and_statuses() -> None:
    result = validate_nvd_page(encoded(example_page()))
    assert result["row_count"] == 2
    assert result["reported_total_results"] == 2
    assert result["coverage_scope"] == "single_response_page_only"
    assert result["status_counts"] == {"Analyzed": 1, "Awaiting Analysis": 1}


def test_idempotent_archiving_preserves_original_retrieval_time(tmp_path: Path) -> None:
    payload = encoded(example_page())
    first = archive_nvd_page(tmp_path, page_bytes=payload)
    repeat = archive_nvd_page(tmp_path, page_bytes=payload)
    assert first["status"] == "ingested"
    assert repeat["status"] == "skipped_existing"
    assert first["retrieved_at_utc"] == repeat["retrieved_at_utc"]
    assert first["snapshot_id"] == hashlib.sha256(payload).hexdigest()
    assert (Path(first["snapshot_path"]) / "page.json").read_bytes() == payload
    assert len(list((tmp_path / "raw" / "nvd").iterdir())) == 1


@pytest.mark.parametrize(
    "edit,pattern",
    [
        (lambda r: r.update(format="NVD_CPE"), "format"),
        (lambda r: r.update(version="1.0"), "format"),
        (lambda r: r.update(startIndex=-1), "startIndex"),
        (lambda r: r.update(totalResults=1), "pagination"),
        (lambda r: r.update(resultsPerPage=True), "integer"),
        (lambda r: r.update(timestamp="invalid"), "timestamp"),
        (lambda r: r.update(vulnerabilities=[]), "no CVE"),
        (
            lambda r: r["vulnerabilities"][1]["cve"].update(id="CVE-2026-12345"),
            "Duplicate CVE",
        ),
        (lambda r: r["vulnerabilities"][0]["cve"].update(id="ABC"), "Invalid CVE"),
        (lambda r: r["vulnerabilities"][0]["cve"].update(published="yesterday"), "timestamp"),
        (lambda r: r["vulnerabilities"][0]["cve"].update(vulnStatus=None), "status"),
        (lambda r: r["vulnerabilities"][0]["cve"].update(metrics=[]), "metrics"),
        (lambda r: r["vulnerabilities"][0]["cve"].pop("descriptions"), "descriptions"),
    ],
)
def test_invalid_page_fails_closed(tmp_path: Path, edit, pattern: str) -> None:
    record = copy.deepcopy(example_page())
    edit(record)
    with pytest.raises(NVDIngestionError, match=pattern):
        archive_nvd_page(tmp_path, page_bytes=encoded(record))
    assert not (tmp_path / "raw" / "nvd").exists()


def test_non_object_and_malformed_json_rejected() -> None:
    for payload in (b"[]", b"{", b"", b"\xff"):
        with pytest.raises(NVDIngestionError):
            validate_nvd_page(payload)


def test_bounded_payload_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import patchline.ingest.nvd as nvd

    monkeypatch.setattr(nvd, "MAX_PAGE_BYTES", 100)
    with pytest.raises(NVDIngestionError, match="size limit"):
        validate_nvd_page(encoded(example_page()))


def test_manifest_tampering_rejected(tmp_path: Path) -> None:
    payload = encoded(example_page())
    result = archive_nvd_page(tmp_path, page_bytes=payload)
    marker = Path(result["snapshot_path"]) / "manifest.json"
    record = json.loads(marker.read_text(encoding="utf-8"))
    record["row_count"] = 999
    marker.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(NVDIngestionError, match="manifest mismatch"):
        archive_nvd_page(tmp_path, page_bytes=payload)


def test_source_tampering_rejected(tmp_path: Path) -> None:
    payload = encoded(example_page())
    result = archive_nvd_page(tmp_path, page_bytes=payload)
    (Path(result["snapshot_path"]) / "page.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(NVDIngestionError, match="hash mismatch"):
        archive_nvd_page(tmp_path, page_bytes=payload)


def test_incomplete_manifest_write_can_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import patchline.ingest.nvd as nvd

    original = nvd._atomic_write_new

    def interrupt(path: Path, content: bytes) -> None:
        if path.name == "manifest.json":
            raise OSError("synthetic disk interruption")
        original(path, content)

    monkeypatch.setattr(nvd, "_atomic_write_new", interrupt)
    with pytest.raises(OSError, match="disk interruption"):
        archive_nvd_page(tmp_path, page_bytes=encoded(example_page()))
    assert not list((tmp_path / "raw" / "nvd").glob("*/manifest.json"))
    monkeypatch.setattr(nvd, "_atomic_write_new", original)
    assert archive_nvd_page(tmp_path, page_bytes=encoded(example_page()))["status"] == "ingested"


def test_cli_explicit_file_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "synthetic-nvd.json"
    source.write_bytes(encoded(example_page()))
    assert main(["--file", str(source), "--data-dir", str(tmp_path / "archive")]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["status"] == "ingested"
    assert response["query_parameters_verified"] is False


def test_cli_rejects_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--file", str(tmp_path / "absent.json")]) == 1
    assert "missing" in capsys.readouterr().err


def test_sample_fixture_is_explicitly_single_page() -> None:
    fixture = Path(__file__).parent / "fixtures" / "nvd-synthetic-page.json"
    metadata = validate_nvd_page(fixture.read_bytes())
    assert metadata["coverage_scope"] == "single_response_page_only"
    assert metadata["row_count"] == 2
