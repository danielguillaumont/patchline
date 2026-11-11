"""Deterministic offline tests for the KEV ingestion boundary."""

import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchline.ingest.kev import KEVIngestionError, ingest_kev, validate_kev


def encoded(obj: dict) -> bytes:
    return json.dumps(obj).encode("utf-8")


def test_validate_reconciles_and_preserves_count(catalog: dict, schema: dict) -> None:
    assert validate_kev(encoded(catalog), encoded(schema))["count"] == 2


def test_duplicate_cve_rejected(catalog: dict, schema: dict) -> None:
    bad = copy.deepcopy(catalog)
    bad["vulnerabilities"][1]["cveID"] = bad["vulnerabilities"][0]["cveID"]
    with pytest.raises(KEVIngestionError, match="Duplicate CVE"):
        validate_kev(encoded(bad), encoded(schema))


def test_count_mismatch_rejected(catalog: dict, schema: dict) -> None:
    bad = {**catalog, "count": 7}
    with pytest.raises(KEVIngestionError, match="count"):
        validate_kev(encoded(bad), encoded(schema))


def test_bad_date_rejected(catalog: dict, schema: dict) -> None:
    bad = copy.deepcopy(catalog)
    bad["vulnerabilities"][0]["dateAdded"] = "not-a-date"
    with pytest.raises(KEVIngestionError):
        validate_kev(encoded(bad), encoded(schema))


def test_reingest_is_idempotent(tmp_path: Path, catalog: dict, schema: dict) -> None:
    raw = encoded(catalog)
    source_schema = encoded(schema)
    first = ingest_kev(tmp_path, catalog_bytes=raw, schema_bytes=source_schema)
    second = ingest_kev(tmp_path, catalog_bytes=raw, schema_bytes=source_schema)
    assert first["status"] == "ingested"
    assert second["status"] == "skipped_existing"
    assert first["snapshot_id"] == hashlib.sha256(raw).hexdigest()
    assert len(list((tmp_path / "raw" / "kev").iterdir())) == 1
    assert first["retrieved_at_utc"] == second["retrieved_at_utc"]
    datetime.fromisoformat(first["retrieved_at_utc"].replace("Z", "+00:00")).astimezone(UTC)


def test_failed_validation_does_not_create_snapshot(tmp_path: Path, catalog: dict, schema: dict) -> None:
    with pytest.raises(KEVIngestionError):
        ingest_kev(tmp_path, catalog_bytes=b"{", schema_bytes=encoded(schema))
    assert not (tmp_path / "raw" / "kev").exists()


def test_tampered_snapshot_is_detected(tmp_path: Path, catalog: dict, schema: dict) -> None:
    raw = encoded(catalog)
    first = ingest_kev(tmp_path, catalog_bytes=raw, schema_bytes=encoded(schema))
    (Path(first["snapshot_path"]) / "catalog.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(KEVIngestionError, match="hash mismatch"):
        ingest_kev(tmp_path, catalog_bytes=raw, schema_bytes=encoded(schema))
