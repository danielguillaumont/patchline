"""Offline checks for the intentionally tiny dbt CI warehouse fixture."""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from patchline.fixtures.ci_warehouse import create_fixture, verify_joins, verify_m03, verify_staging


def test_fixture_raw_schema_counts_and_lineage(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with duckdb.connect(str(output), read_only=True) as con:
        assert con.execute("SELECT COUNT(*) FROM main.source_snapshots").fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM main.raw_kev_snapshot").fetchone()[0] == 3
        assert con.execute("SELECT COUNT(*) FROM main.raw_epss_daily").fetchone()[0] == 4
        assert con.execute("SELECT COUNT(DISTINCT cve_id) FROM main.raw_kev_snapshot").fetchone()[0] == 3
        assert con.execute("SELECT COUNT(DISTINCT cve_id) FROM main.raw_epss_daily").fetchone()[0] == 4
        assert con.execute("SELECT COUNT(*) FROM main.raw_epss_daily WHERE epss IN (0, 1)").fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM main.raw_kev_snapshot WHERE product = ''").fetchone()[0] == 1


def test_fixture_refuses_to_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    before = output.read_bytes()
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        create_fixture(output)
    assert output.read_bytes() == before


def test_fixture_requires_existing_parent(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Output directory does not exist"):
        create_fixture(tmp_path / "missing" / "ci.duckdb")


def test_verify_requires_staging_views(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with pytest.raises(ValueError, match="Unexpected staging objects"):
        verify_staging(output)


def test_verify_rejects_unexpected_snapshot_id(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with duckdb.connect(str(output)) as con:
        con.execute("CREATE SCHEMA analytics_staging")
        con.execute("CREATE VIEW analytics_staging.stg_kev AS SELECT * FROM main.raw_kev_snapshot")
        con.execute("CREATE VIEW analytics_staging.stg_epss AS SELECT * FROM main.raw_epss_daily")
        con.execute("UPDATE main.source_snapshots SET snapshot_id = 'tampered' WHERE source = 'kev'")
    with pytest.raises(ValueError, match="Unexpected synthetic snapshot lineage"):
        verify_staging(output)


def test_join_verifier_requires_staging_first(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with pytest.raises(ValueError, match="Unexpected staging objects"):
        verify_joins(output)


def test_join_verifier_requires_intermediate_view(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with duckdb.connect(str(output)) as con:
        con.execute("CREATE SCHEMA analytics_staging")
        con.execute("""CREATE VIEW analytics_staging.stg_kev AS
            SELECT * FROM main.raw_kev_snapshot""")
        con.execute("""CREATE VIEW analytics_staging.stg_epss AS
            SELECT * FROM main.raw_epss_daily""")
    with pytest.raises(ValueError, match="Unexpected intermediate objects"):
        verify_joins(output)


def test_m03_verifier_requires_staging_first(tmp_path: Path) -> None:
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with pytest.raises(ValueError, match="Unexpected staging objects"):
        verify_m03(output)


def test_m03_verifier_rejects_missing_mart(tmp_path: Path) -> None:
    """A source-only fixture can never be mistaken for computed M03 evidence."""
    output = tmp_path / "ci.duckdb"
    create_fixture(output)
    with duckdb.connect(str(output)) as con:
        con.execute("CREATE SCHEMA analytics_staging")
        con.execute("""CREATE VIEW analytics_staging.stg_kev AS
            SELECT * FROM main.raw_kev_snapshot""")
        con.execute("""CREATE VIEW analytics_staging.stg_epss AS
            SELECT * FROM main.raw_epss_daily""")
    with pytest.raises(ValueError, match="Unexpected intermediate objects"):
        verify_m03(output)
