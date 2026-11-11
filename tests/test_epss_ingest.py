"""Deterministic EPSS bulk ingestion and corruption regression tests."""

import gzip
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from patchline.ingest import epss
from patchline.ingest.epss import EPSSIngestionError, ingest_epss, validate_epss


def feed(rows: str = "CVE-2025-1234,0.00012,0.55555\nCVE-2026-9876,1,1\n") -> bytes:
    text = "#model_version:v2026.06.15,score_date:2026-11-10T12:00:00Z\n"
    return gzip.compress((text + "cve,epss,percentile\n" + rows).encode("utf-8"), mtime=0)


def test_good_feed_metadata_and_precision() -> None:
    assert validate_epss(feed()) == {
        "model_version": "v2026.06.15",
        "score_date": "2026-11-10T12:00:00Z",
        "row_count": 2,
    }


def test_repeat_ingestion_preserves_manifest(tmp_path: Path) -> None:
    data = feed()
    first = ingest_epss(tmp_path, compressed_bytes=data)
    second = ingest_epss(tmp_path, compressed_bytes=data)
    assert first["status"] == "ingested"
    assert second["status"] == "skipped_existing"
    assert second["retrieved_at_utc"] == first["retrieved_at_utc"]
    assert first["snapshot_id"] == hashlib.sha256(data).hexdigest()
    assert (Path(first["snapshot_path"]) / "scores.csv.gz").read_bytes() == data
    assert len(list((tmp_path / "raw" / "epss").iterdir())) == 1


@pytest.mark.parametrize("rows,pattern", [
    ("CVE-2025-1234,0.1,0.1\nCVE-2025-1234,0.2,0.2\n", "Duplicate"),
    ("not-a-cve,0.1,0.1\n", "Invalid EPSS CVE"),
    ("CVE-2025-1234,1.01,0.1\n", "Out-of-range epss"),
    ("CVE-2025-1234,0.1,NaN\n", "Out-of-range percentile"),
    ("CVE-2025-1234,invalid,0.1\n", "Invalid epss"),
    ("", "Empty EPSS"),
])
def test_invalid_rows_rejected_without_publishing(tmp_path: Path, rows: str, pattern: str) -> None:
    with pytest.raises(EPSSIngestionError, match=pattern):
        ingest_epss(tmp_path, compressed_bytes=feed(rows))
    assert not (tmp_path / "raw" / "epss").exists()


def test_truncated_gzip_rejected() -> None:
    with pytest.raises(EPSSIngestionError, match="truncated|Malformed"):
        validate_epss(feed()[:-7])


def test_bad_metadata_rejected() -> None:
    wrong = gzip.compress(b"cve,epss,percentile\nCVE-2025-1234,0.1,0.2\n")
    with pytest.raises(EPSSIngestionError, match="metadata"):
        validate_epss(wrong)


def test_corrupt_archived_gzip_rejected(tmp_path: Path) -> None:
    result = ingest_epss(tmp_path, compressed_bytes=feed())
    (Path(result["snapshot_path"]) / "scores.csv.gz").write_bytes(b"changed")
    with pytest.raises(EPSSIngestionError, match="hash mismatch"):
        ingest_epss(tmp_path, compressed_bytes=feed())


def test_tampered_manifest_rejected(tmp_path: Path) -> None:
    result = ingest_epss(tmp_path, compressed_bytes=feed())
    path = Path(result["snapshot_path"]) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["row_count"] = 7
    path.write_text(json.dumps(manifest))
    with pytest.raises(EPSSIngestionError, match="manifest mismatch"):
        ingest_epss(tmp_path, compressed_bytes=feed())


def test_incomplete_write_can_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = epss._atomic_write_new

    def fail_marker(path: Path, content: bytes) -> None:
        if path.name == "manifest.json":
            raise OSError("disk full")
        original(path, content)

    monkeypatch.setattr(epss, "_atomic_write_new", fail_marker)
    with pytest.raises(OSError, match="disk full"):
        ingest_epss(tmp_path, compressed_bytes=feed())
    assert not list((tmp_path / "raw" / "epss").glob("*/manifest.json"))
    monkeypatch.setattr(epss, "_atomic_write_new", original)
    assert ingest_epss(tmp_path, compressed_bytes=feed())["status"] == "ingested"


def test_http_timeout_leaves_no_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_client: httpx.Client) -> bytes:
        raise httpx.ReadTimeout("synthetic timeout")

    monkeypatch.setattr(epss, "_download", fail)
    with pytest.raises(EPSSIngestionError, match="download failed"):
        ingest_epss(tmp_path)
    assert not (tmp_path / "raw" / "epss").exists()
