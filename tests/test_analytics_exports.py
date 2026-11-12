"""Offline, nonnetwork contract checks for validated P3.4A export bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import duckdb
import pytest

from patchline.exports.analytics import (
    ExportError,
    _enforce_consumer_contract,
    export_bundle,
    verify_bundle,
)
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
                (200.0 / 3.0)::DOUBLE AS coverage_percent,
                '2026-01-15T12:00:00Z' AS kev_retrieved_at_utc,
                '2026-01-15T12:30:00Z' AS epss_retrieved_at_utc,
                'v-ci-synthetic' AS epss_model_version""")
        con.execute(f"""CREATE VIEW analytics_marts.m04_epss_population_summary AS
            SELECT 'M04' AS metric_id, '{EPSS_ID}' AS epss_snapshot_id,
                '2026-01-15' AS epss_source_date,
                4::BIGINT AS scored_cve_count""")
        con.execute(f"""CREATE TABLE analytics_marts.m04_epss_score_bands AS
            SELECT 'M04'::VARCHAR AS metric_id, '{EPSS_ID}'::VARCHAR AS epss_snapshot_id,
                '2026-01-15'::VARCHAR AS epss_source_date,
                band_order, band_label, lower_bound, upper_bound,
                (band_order = 5) AS upper_inclusive, cve_count,
                4::BIGINT AS denominator_scored_cves,
                25.0 * cve_count AS population_percent
            FROM (VALUES
                (1, '0.000 to <0.001', 0.000::DOUBLE, 0.001::DOUBLE, 1::BIGINT),
                (2, '0.001 to <0.010', 0.001::DOUBLE, 0.010::DOUBLE, 0::BIGINT),
                (3, '0.010 to <0.100', 0.010::DOUBLE, 0.100::DOUBLE, 1::BIGINT),
                (4, '0.100 to <0.500', 0.100::DOUBLE, 0.500::DOUBLE, 0::BIGINT),
                (5, '0.500 to 1.000 inclusive', 0.500::DOUBLE, 1.000::DOUBLE, 2::BIGINT)
            ) AS b(band_order, band_label, lower_bound, upper_bound, cve_count)""")
        con.execute(f"""CREATE TABLE analytics_marts.m05_kev_epss_cohort_bands AS
            WITH scored AS (
                SELECT 'M05' AS metric_id, '{KEV_ID}' AS kev_snapshot_id,
                    '{EPSS_ID}' AS epss_snapshot_id,
                    '2026-01-15T00:00:00Z' AS kev_catalog_date_released,
                    '2026-01-15' AS epss_source_date,
                    '2026-01-15T12:00:00Z' AS kev_retrieved_at_utc,
                    '2026-01-15T12:30:00Z' AS epss_retrieved_at_utc,
                    'v-ci-synthetic' AS epss_model_version,
                    band_order, 'scored_band' AS cohort_category, band_label,
                    lower_bound, upper_bound, upper_inclusive,
                    (CASE WHEN band_order IN (3, 5) THEN 1 ELSE 0 END)::BIGINT AS kev_cve_count,
                    3::BIGINT AS denominator_all_kev,
                    2::BIGINT AS denominator_scored_kev,
                    1::BIGINT AS unscored_kev,
                    CASE WHEN band_order IN (3, 5) THEN 100.0 / 3.0 ELSE 0.0 END
                        AS share_all_kev_percent,
                    CASE WHEN band_order IN (3, 5) THEN 50.0 ELSE 0.0 END
                        AS share_scored_kev_percent,
                    cve_count AS full_epss_band_count,
                    denominator_scored_cves AS full_epss_denominator,
                    population_percent AS full_epss_population_percent
                FROM analytics_marts.m04_epss_score_bands
            )
            SELECT * FROM scored
            UNION ALL
            SELECT 'M05', '{KEV_ID}', '{EPSS_ID}',
                '2026-01-15T00:00:00Z', '2026-01-15',
                '2026-01-15T12:00:00Z', '2026-01-15T12:30:00Z', 'v-ci-synthetic',
                6, 'unscored_kev', 'No matching EPSS score',
                NULL::DOUBLE, NULL::DOUBLE, NULL::BOOLEAN,
                1::BIGINT, 3::BIGINT, 2::BIGINT, 1::BIGINT,
                100.0 / 3.0, NULL::DOUBLE,
                NULL::BIGINT, NULL::BIGINT, NULL::DOUBLE""")


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


def test_consumer_manifest_rejects_unknown_kind() -> None:
    with pytest.raises(ExportError, match="Consumer contract manifest"):
        _enforce_consumer_contract("manifest", {"schema_id": "patchline.analytics-export.v1",
                                                 "data_kind": "live_now"})

def test_consumer_m03_rejects_percentage_out_of_range() -> None:
    row = {"metric_id": "M03", "kev_snapshot_id": "kev", "epss_snapshot_id": "epss",
           "kev_catalog_date_released": "2026-01-15", "epss_source_date": "2026-01-15",
           "numerator_matched_kev": 2, "denominator_total_kev": 3,
           "unmatched_kev": 1, "coverage_percent": 101.0}
    with pytest.raises(ExportError, match="Consumer contract m03"):
        _enforce_consumer_contract("m03_epss_coverage_of_kev", [row])

def test_consumer_m04_rejects_negative_population() -> None:
    row = {"metric_id": "M04", "epss_snapshot_id": "epss",
           "epss_source_date": "2026-01-15", "scored_cve_count": -1}
    with pytest.raises(ExportError, match="Consumer contract m04"):
        _enforce_consumer_contract("m04_epss_population_summary", [row])


def test_v2_export_roundtrip_preserves_v1_default(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    legacy = export_bundle(database, tmp_path / "legacy")
    assert legacy["schema_id"] == "patchline.analytics-export.v1"
    assert len(legacy["artifacts"]) == 9
    assert all("m05" not in item["path"] for item in legacy["artifacts"])
    modern = export_bundle(database, tmp_path / "modern", contract="v2")
    assert modern["schema_id"] == "patchline.analytics-export.v2"
    assert len(modern["artifacts"]) == 12
    assert len(verify_bundle(tmp_path / "legacy")["artifacts"]) == 9
    assert len(verify_bundle(tmp_path / "modern")["artifacts"]) == 12
    rows = json.loads((tmp_path / "modern/m05_kev_epss_cohort_bands.json").read_text())
    assert len(rows) == 6
    assert [r["kev_cve_count"] for r in rows] == [0, 0, 1, 0, 1, 1]
    assert [r["cohort_category"] for r in rows] == ["scored_band"] * 5 + ["unscored_kev"]
    assert rows[5]["share_scored_kev_percent"] is None
    assert rows[5]["full_epss_population_percent"] is None
    assert [item["rows"] for item in modern["artifacts"] if item["model"].startswith("m05_")] == [6, 6, 6]


def test_v2_requires_m05_and_never_publishes_incomplete_bundle(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    with duckdb.connect(str(database)) as con:
        con.execute("DROP TABLE analytics_marts.m05_kev_epss_cohort_bands")
    with pytest.raises(ExportError, match="M05 export prerequisites failed"):
        export_bundle(database, tmp_path / "v2", contract="v2")
    assert not (tmp_path / "v2").exists()
    assert not list(tmp_path.glob(".patchline-export-*"))
    assert len(export_bundle(database, tmp_path / "v1")["artifacts"]) == 9


def test_v2_rejects_m05_denominator_tampering(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    with duckdb.connect(str(database)) as con:
        con.execute("""UPDATE analytics_marts.m05_kev_epss_cohort_bands
            SET denominator_all_kev = 999 WHERE band_order = 3""")
    with pytest.raises(ExportError, match="M05 source lineage or denominator mismatch"):
        export_bundle(database, tmp_path / "invalid", contract="v2")
    assert not (tmp_path / "invalid").exists()


def test_v2_rejects_unscored_kev_imputation(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    with duckdb.connect(str(database)) as con:
        con.execute("""UPDATE analytics_marts.m05_kev_epss_cohort_bands
            SET share_scored_kev_percent = 0 WHERE band_order = 6""")
    with pytest.raises(ExportError, match="unmatched cohort"):
        export_bundle(database, tmp_path / "invalid", contract="v2")


def test_v2_verify_detects_changed_json_even_if_digest_rewritten(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    create_fixture(database)
    _seed_aggregate_marts(database)
    bundle = tmp_path / "v2"
    export_bundle(database, bundle, contract="v2")
    file = bundle / "m05_kev_epss_cohort_bands.json"
    data = json.loads(file.read_text(encoding="utf-8"))
    data[0]["kev_cve_count"] = 1
    data[0]["share_all_kev_percent"] = 100.0 / 3.0
    data[0]["share_scored_kev_percent"] = 50.0
    file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    item = next(x for x in manifest["artifacts"] if x["path"] == file.name)
    item["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
    item["bytes"] = file.stat().st_size
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ExportError, match="M05 scored cohort counts do not reconcile"):
        verify_bundle(bundle)


def test_v2_unknown_contract_refused(tmp_path: Path) -> None:
    with pytest.raises(ExportError, match="Unsupported analytical export contract"):
        export_bundle(tmp_path / "irrelevant.duckdb", tmp_path / "v3", contract="v3")


def test_v2_manifest_consumer_contract_rejects_v1_shape() -> None:
    with pytest.raises(ExportError, match="Consumer contract manifest.v2"):
        _enforce_consumer_contract("manifest.v2", {"schema_id": "patchline.analytics-export.v1"})
