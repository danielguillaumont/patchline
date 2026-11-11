"""Offline fault-injection regression tests for KEV snapshot recovery."""

import json
from pathlib import Path

import httpx
import pytest
from test_kev_ingest import encoded

from patchline.ingest import kev
from patchline.ingest.kev import KEVIngestionError, ingest_kev


def _snapshot(tmp_path: Path, catalog: dict, schema: dict) -> Path:
    result = ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))
    return Path(result["snapshot_path"])


def test_corrupt_schema_rejected(tmp_path: Path, catalog: dict, schema: dict) -> None:
    folder = _snapshot(tmp_path, catalog, schema)
    (folder / "schema.json").write_bytes(b"tampered")
    with pytest.raises(KEVIngestionError, match="schema hash mismatch"):
        ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))


def test_manifest_metadata_tampering_rejected(tmp_path: Path, catalog: dict, schema: dict) -> None:
    folder = _snapshot(tmp_path, catalog, schema)
    manifest = folder / "manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["row_count"] = 1000000
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(KEVIngestionError, match="manifest mismatch: row_count"):
        ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))


def test_malformed_manifest_rejected(tmp_path: Path, catalog: dict, schema: dict) -> None:
    folder = _snapshot(tmp_path, catalog, schema)
    (folder / "manifest.json").write_bytes(b"{")
    with pytest.raises(KEVIngestionError, match="manifest is invalid JSON"):
        ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))


def test_missing_archived_file_rejected(tmp_path: Path, catalog: dict, schema: dict) -> None:
    folder = _snapshot(tmp_path, catalog, schema)
    (folder / "schema.json").unlink()
    with pytest.raises(KEVIngestionError, match="Incomplete existing snapshot"):
        ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))


def test_interrupted_write_retries_without_false_success(
    tmp_path: Path, catalog: dict, schema: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = kev._atomic_write_new

    def interrupted(path: Path, content: bytes) -> None:
        if path.name == "schema.json":
            raise OSError("simulated disk failure")
        original(path, content)

    monkeypatch.setattr(kev, "_atomic_write_new", interrupted)
    with pytest.raises(OSError, match="simulated disk failure"):
        ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))
    folder = tmp_path / "raw" / "kev"
    assert not list(folder.glob("*/manifest.json"))
    monkeypatch.setattr(kev, "_atomic_write_new", original)
    result = ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))
    assert result["status"] == "ingested"
    assert (Path(result["snapshot_path"]) / "manifest.json").is_file()


@pytest.mark.parametrize("error", [httpx.ReadTimeout("timed out"), httpx.HTTPStatusError(
    "503", request=httpx.Request("GET", kev.CATALOG_URL),
    response=httpx.Response(503)
)])
def test_network_errors_do_not_publish_snapshot(
    tmp_path: Path, error: httpx.HTTPError, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_client: httpx.Client, _url: str) -> bytes:
        raise error

    monkeypatch.setattr(kev, "_download", fail)
    with pytest.raises(KEVIngestionError, match="CISA download failed"):
        ingest_kev(tmp_path)
    assert not (tmp_path / "raw" / "kev").exists()


def test_retrieval_timestamp_tamper_rejected(tmp_path: Path, catalog: dict, schema: dict) -> None:
    folder = _snapshot(tmp_path, catalog, schema)
    path = folder / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["retrieved_at_utc"] = "not-a-time"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(KEVIngestionError, match="invalid retrieval time"):
        ingest_kev(tmp_path, catalog_bytes=encoded(catalog), schema_bytes=encoded(schema))
