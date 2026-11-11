"""Offline, nonnetwork contract checks for validated P3.4A export bundles."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest

from patchline.exports.analytics import ExportError, export_bundle, verify_bundle
from patchline.fixtures.ci_warehouse import EPSS_ID, KEV_ID, create_fixture


def _seed_aggregate_marts(database: Path) -> None:
    """Use synthetic SQL aggregates to unit-test exporter independent of dbt execution."""
    with duckdb.connect(str(database)) as con:
        con.execute("CREATE SCHEMA analytics_marts")
        con.execute(f"""CREATE VIEW analytics_marts.m03_epss_coverage_of_kev AS
            SELECT 'M03' AS metric_id, '{KEV_ID}' AS kev_snapshot_id, '{EPSS_ID}' AS epss_snapshot_id,
                '2026-01-15T00:00:00Z' AS kev_catalog_date_released,
                '2026-01-15' AS epss_source_date,
                2::BIGINT AS numerator_matched_kev,
                3::BIGINT AS denominator_total_kev,
                1::BIGINT AS unmatched_kev,
                (200.0 / 3.0)::DOUBLE AS coverage_percent""")
        con.execute(f"""CREATE VIEW analytics_marts.m04_epss_population_summary AS
            SELECT 'M04' AS metric_id, '{EPSS_ID}' AS epss_snapshot_id,
                '2026-01-15' AS epss_source_date,
                4::BIGINT AS scored_cve_count""")
        con.execute(f"""CREATE TABLE analytics_marts.m04_epss_score_bands AS
            SELECT 'M04'::VARCHAR AS metric_id, '{EPSS_ID}'::VARCHAR AS epss_snapshot_id,
                '2026-01-15'::VARCHAR AS epss_source_date,
                band_order, cve_count, 4::BIGINT AS denominator_scored_cves,
                25.0 * cve_count AS population_percent
            FROM (VALUES (1, 1::BIGINT), (2, 0::BIGINT), (3, 1::BIGINT),
                (4, 0::BIGINT), (5, 2::BIGINT)) AS b(band_order, cve_count)""")


def test_export_refuses_incomplete_warehouse(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    output = tmp_path / "report"
    with pytest.raises(ExportError, match="prerequisites failed"):
        export_bundle(database, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".patchline-export-*"))


def test_export_roundtrip_and_integrity(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    output = tmp_path / "report"
    manifest = export_bundle(database, output)
    assert manifest["schema_id"] == "patchline.analytics-export.v1"
    assert manifest["data_kind"] == "synthetic_fixture"
    assert manifest["validation"] == {
        "kev_total": 3, "kev_matched": 2, "kev_unmatched": 1, "epss_scored_total": 4,
    }
    assert len(manifest["artifacts"]) == 9
    assert len(verify_bundle(output)["artifacts"]) == 9
    assert len(json.loads((output / "m04_epss_score_bands.json").read_text())) == 5
    assert (output / "m03_epss_coverage_of_kev.parquet").is_file()
    with pytest.raises(ExportError, match="Refusing to overwrite"):
        export_bundle(database, output)
    csv_path = output / "m03_epss_coverage_of_kev.csv"
    csv_path.write_bytes(csv_path.read_bytes() + b"tampered")
    with pytest.raises(ExportError, match="digest mismatch|altered export"):
        verify_bundle(output)


def test_export_rejects_unreconciled_population(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    with duckdb.connect(str(database)) as con:
        con.execute("""UPDATE analytics_marts.m04_epss_score_bands
            SET cve_count = 3 WHERE band_order = 5""")
    with pytest.raises(ExportError, match="EPSS score bands do not reconcile"):
        export_bundle(database, tmp_path / "invalid")
    assert not (tmp_path / "invalid").exists()
