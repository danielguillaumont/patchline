"""Offline snapshot-to-DuckDB tests; no network or live data required."""

import gzip
import json
from pathlib import Path

import pytest

from patchline.ingest.epss import ingest_epss
from patchline.ingest.kev import ingest_kev
from patchline.warehouse.build import WarehouseError, build_warehouse


def _encode(value: dict) -> bytes:
    return json.dumps(value).encode("utf-8")


def _archives(tmp_path: Path, catalog: dict, schema: dict) -> tuple[dict, dict]:
    kev = ingest_kev(tmp_path, catalog_bytes=_encode(catalog), schema_bytes=_encode(schema))
    contents = (
        "#model_version:v2026.06.15,score_date:2026-11-10T12:00:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2025-0001,0.123456,0.7\n"
        "CVE-2026-9999,0.99,0.999\n"
    )
    epss = ingest_epss(tmp_path, compressed_bytes=gzip.compress(contents.encode(), mtime=0))
    return kev, epss


def test_build_and_reconcile(tmp_path: Path, catalog: dict, schema: dict) -> None:
    duckdb = pytest.importorskip("duckdb")
    kev, epss = _archives(tmp_path, catalog, schema)
    destination = tmp_path / "warehouse" / "patchline.duckdb"
    result = build_warehouse(tmp_path, destination)
    assert result["kev_rows"] == 2
    assert result["epss_rows"] == 2
    assert result["kev_snapshot_id"] == kev["snapshot_id"]
    assert result["epss_snapshot_id"] == epss["snapshot_id"]
    with duckdb.connect(str(destination), read_only=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM source_snapshots").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM raw_kev_snapshot").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM raw_epss_daily").fetchone()[0] == 2
        assert connection.execute(
            "SELECT epss FROM raw_epss_daily WHERE cve_id='CVE-2025-0001'"
        ).fetchone()[0] == pytest.approx(0.123456)
    with pytest.raises(WarehouseError, match="already exists"):
        build_warehouse(tmp_path, destination)


def test_tampered_archive_fails_without_database(
    tmp_path: Path, catalog: dict, schema: dict
) -> None:
    kev, _ = _archives(tmp_path, catalog, schema)
    (Path(kev["snapshot_path"]) / "catalog.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "warehouse" / "patchline.duckdb"
    with pytest.raises(WarehouseError, match="SHA-256"):
        build_warehouse(tmp_path, output)
    assert not output.exists()


def test_tampered_manifest_fails(tmp_path: Path, catalog: dict, schema: dict) -> None:
    _, epss = _archives(tmp_path, catalog, schema)
    manifest = Path(epss["snapshot_path"]) / "manifest.json"
    content = json.loads(manifest.read_text(encoding="utf-8"))
    content["row_count"] += 1
    manifest.write_text(json.dumps(content), encoding="utf-8")
    with pytest.raises(WarehouseError, match="metadata mismatch"):
        build_warehouse(tmp_path, tmp_path / "warehouse.duckdb")


def test_ambiguous_snapshots_require_explicit_selection(
    tmp_path: Path, catalog: dict, schema: dict
) -> None:
    _archives(tmp_path, catalog, schema)
    extra = tmp_path / "raw" / "epss" / ("0" * 64)
    extra.mkdir(parents=True)
    with pytest.raises(WarehouseError, match="select one explicitly"):
        build_warehouse(tmp_path, tmp_path / "warehouse.duckdb")
