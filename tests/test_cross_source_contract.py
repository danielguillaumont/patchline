"""EA-03A4C: offline selection checks; never join data or fetch remote sources."""

from __future__ import annotations

import hashlib
from pathlib import Path

import duckdb
import pytest

from patchline.fixtures.ci_warehouse import create_fixture
from patchline.warehouse.cross_source_contract import (
    SourceContractError,
    inspect_source_selection,
    main,
)
from patchline.warehouse.nvd_stage import _ddl

QUERY = "a" * 64


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def databases(tmp_path: Path) -> tuple[Path, Path]:
    analytics = tmp_path / "analytics.duckdb"
    nvd = tmp_path / "nvd.duckdb"
    create_fixture(analytics)
    with duckdb.connect(str(nvd)) as con:
        _ddl(con)
        con.execute(
            "INSERT INTO nvd_stage.query_registry VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                "patchline.nvd-duckdb-query-staging.v1", QUERY, "b" * 64, "c" * 64,
                "NVD_CVE", "last_modified_window", 2, 2, 1,
                False, False, False, False,
            ],
        )
        con.executemany(
            "INSERT INTO nvd_stage.cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                [QUERY, 0, "CVE-2099-0001", "example", "Analyzed",
                 "2099-01-01T00:00:00.000", "2099-01-02T00:00:00.000",
                 "Synthetic NVD record", "d" * 64, 0, 0,
                 False, False, False, False, False, "{}"],
                [QUERY, 1, "CVE-2099-0002", "example", "Analyzed",
                 "2099-01-01T00:00:00.000", "2099-01-02T00:00:00.000",
                 None, "d" * 64, 0, 1,
                 True, True, True, True, True, "{}"],
            ],
        )
        con.executemany(
            "INSERT INTO nvd_stage.cvss_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                [QUERY, "CVE-2099-0001", 0, "cvssMetricV31", "3.1", "test", "Primary",
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL", "{}"],
                [QUERY, "CVE-2099-0001", 1, "cvssMetricV40", "4.0", "test", "Secondary",
                 None, None, "HIGH", "{}"],
            ],
        )
    return analytics, nvd


def _inspect(databases: tuple[Path, Path]) -> dict:
    analytics, nvd = databases
    return inspect_source_selection(analytics_database=analytics, nvd_database=nvd)


def test_valid_fixture_remains_read_only_and_no_join(databases) -> None:
    before = [_digest(path) for path in databases]
    result = _inspect(databases)
    assert result["schema_id"] == "exploit-atlas.cross-source-selection.v1"
    assert result["status"] == "source_selection_validated_no_join"
    assert result["kev"]["row_count"] == 3
    assert result["epss"]["row_count"] == 4
    assert result["nvd"]["cve_count"] == 2
    assert result["nvd"]["cvss_metric_count"] == 2
    assert result["nvd"]["query_id"] == QUERY
    assert result["cross_source_join_executed"] is False
    assert result["join_approved"] is False
    assert result["point_in_time_alignment_attested"] is False
    assert result["nvd_global_coverage_attested"] is False
    assert result["asset_exposure_known"] is False
    assert result["source_archive_reverified_by_this_command"] is False
    assert [_digest(path) for path in databases] == before


def test_rejects_snapshot_row_count_mismatch(databases) -> None:
    with duckdb.connect(str(databases[0])) as con:
        con.execute("UPDATE main.source_snapshots SET row_count=100 WHERE source='kev'")
    with pytest.raises(SourceContractError, match="raw count"):
        _inspect(databases)


def test_rejects_extra_snapshot_source(databases) -> None:
    with duckdb.connect(str(databases[0])) as con:
        con.execute("INSERT INTO main.source_snapshots VALUES (?,?,?,?,?,?)", [
            "nvd", "c" * 64, "2026-01-15T00:00:00Z", "2026-01-15", None, 0
        ])
    with pytest.raises(SourceContractError, match="exactly one snapshot"):
        _inspect(databases)


def test_rejects_epss_date_mismatch(databases) -> None:
    with duckdb.connect(str(databases[0])) as con:
        con.execute("UPDATE main.raw_epss_daily SET score_date='2026-01-14'")
    with pytest.raises(SourceContractError, match="EPSS score date"):
        _inspect(databases)


def test_rejects_out_of_range_epss(databases) -> None:
    with duckdb.connect(str(databases[0])) as con:
        con.execute("UPDATE main.raw_epss_daily SET epss=1.2")
    with pytest.raises(SourceContractError, match="outside"):
        _inspect(databases)


def test_rejects_wrong_nvd_registry_counts(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.query_registry SET metric_count=3")
    with pytest.raises(SourceContractError, match="CVSS count"):
        _inspect(databases)


def test_rejects_nvd_false_complete_claim(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("""UPDATE nvd_stage.query_registry
                       SET global_nvd_completeness_attested=true""")
    with pytest.raises(SourceContractError, match="falsely asserts"):
        _inspect(databases)


def test_rejects_unexpected_nvd_staging_version(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.query_registry SET contract_version='unexpected'")
    with pytest.raises(SourceContractError, match="staging contract"):
        _inspect(databases)


def test_rejects_nvd_missing_page_lineage(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.cves SET source_page_sha256='invalid'")
    with pytest.raises(SourceContractError, match="page SHA-256"):
        _inspect(databases)


def test_rejects_wrong_metric_query(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.cvss_metrics SET query_id=?", ["f" * 64])
    with pytest.raises(SourceContractError, match="unknown CVE|another query"):
        _inspect(databases)


def test_rejects_noncontiguous_cvss_metric_index(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.cvss_metrics SET metric_index=9 WHERE metric_index=1")
    with pytest.raises(SourceContractError, match="positions"):
        _inspect(databases)


def test_rejects_wrong_database_path(databases, tmp_path: Path) -> None:
    with pytest.raises(SourceContractError, match="separate databases"):
        inspect_source_selection(
            analytics_database=databases[0], nvd_database=databases[0]
        )
    with pytest.raises(SourceContractError, match="missing"):
        inspect_source_selection(
            analytics_database=databases[0], nvd_database=tmp_path / "missing.duckdb"
        )


def test_rejects_same_database_hardlink(databases, tmp_path: Path) -> None:
    import os

    alias = tmp_path / "same-database.duckdb"
    try:
        os.link(databases[0], alias)
    except OSError:
        pytest.skip("Filesystem does not permit hard links")
    with pytest.raises(SourceContractError, match="separate databases"):
        inspect_source_selection(analytics_database=databases[0], nvd_database=alias)


def test_rejects_nvd_symlink(databases, tmp_path: Path) -> None:
    link = tmp_path / "nvd-link.duckdb"
    try:
        link.symlink_to(databases[1])
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(SourceContractError, match="symlinked"):
        inspect_source_selection(analytics_database=databases[0], nvd_database=link)


def test_cli_success_and_failure(databases, tmp_path: Path, capsys) -> None:
    assert main(["--analytics-db", str(databases[0]), "--nvd-db", str(databases[1])]) == 0
    assert '"join_approved": false' in capsys.readouterr().out
    assert main(["--analytics-db", str(databases[0]),
                 "--nvd-db", str(tmp_path / "missing.duckdb")]) == 1
    assert '"status": "failed"' in capsys.readouterr().err
