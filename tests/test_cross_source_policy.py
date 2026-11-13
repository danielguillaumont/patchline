"""EA-03A4D1: synthetic temporal negative tests and read-only integration."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import date
from pathlib import Path

import duckdb
import pytest

from patchline.fixtures.ci_warehouse import create_fixture
from patchline.warehouse.cross_source_policy import (
    TimeCoverageError,
    inspect_time_coverage,
    main,
    validate_time_coverage,
)
from patchline.warehouse.nvd_stage import _ddl

QID = "a" * 64
KEV_ID = hashlib.sha256(b"patchline-ci-synthetic-kev-v1").hexdigest()
EPSS_ID = hashlib.sha256(b"patchline-ci-synthetic-epss-v1").hexdigest()


@pytest.fixture
def selected() -> dict:
    return {
        "schema_id": "exploit-atlas.cross-source-selection.v1",
        "status": "source_selection_validated_no_join",
        "kev": {"snapshot_id": KEV_ID, "source_date": "2026-01-15",
                "retrieved_at_utc": "2026-01-15T12:00:00Z", "row_count": 1},
        "epss": {"snapshot_id": EPSS_ID, "source_date": "2026-01-15",
                 "retrieved_at_utc": "2026-01-15T12:30:00Z", "row_count": 1},
        "nvd": {
            "query_id": QID, "query_mode": "last_modified_window", "source": "NVD_CVE",
            "cve_count": 1,
            "source_scope_flags": {
                "point_in_time_consistency_verified": False,
                "global_nvd_completeness_attested": False,
                "source_origin_independently_verified": False,
                "organization_asset_exposure_known": False,
            },
        },
        "cross_source_join_executed": False,
        "join_approved": False,
        "point_in_time_alignment_attested": False,
        "nvd_global_coverage_attested": False,
        "asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
    }


@pytest.fixture
def rows() -> tuple[list[tuple], list[tuple]]:
    return (
        [(QID, "CVE-2025-0001", "2026-01-01T00:00:00.000",
          "2026-01-12T01:02:03.000")],
        [(KEV_ID, "CVE-2025-0001", date(2026, 1, 10))],
    )


def run(selected, rows, *, cutoff="2026-01-15", ack=True):
    return validate_time_coverage(
        selected, cutoff_date=cutoff, acknowledge_bounded_nvd=ack,
        nvd_cves=rows[0], kev_records=rows[1],
    )


def test_policy_accepted_only_as_bounded_no_join(selected, rows) -> None:
    result = run(selected, rows)
    assert result["schema_id"] == "exploit-atlas.time-coverage-preflight.v1"
    assert result["temporal_precision"] == "calendar_date_only"
    assert result["nvd"]["coverage"] == "bounded_query_only"
    assert result["nvd"]["absence_in_query_proves_not_vulnerable"] is False
    for claim in ("cross_source_join_executed", "join_approved",
                  "historical_as_of_reconstruction_attested",
                  "nvd_global_coverage_attested", "nvd_acquisition_time_verified",
                  "organization_asset_exposure_known", "source_archive_reverified_by_this_command"):
        assert result[claim] is False


def test_acknowledgement_is_required(selected, rows) -> None:
    with pytest.raises(TimeCoverageError, match="acknowledgement"):
        run(selected, rows, ack=False)


@pytest.mark.parametrize("cutoff", ["", "2026/01/15", "2026-02-30", "2026-1-15",
                                     "2026-01-15T00:00:00Z"])
def test_rejects_ambiguous_cutoffs(selected, rows, cutoff) -> None:
    with pytest.raises(TimeCoverageError, match="cutoff"):
        run(selected, rows, cutoff=cutoff)


@pytest.mark.parametrize("field", ["cross_source_join_executed", "join_approved",
                                    "point_in_time_alignment_attested",
                                    "nvd_global_coverage_attested", "asset_exposure_known",
                                    "source_archive_reverified_by_this_command"])
def test_rejects_false_preflight_attestation(selected, rows, field) -> None:
    chosen = deepcopy(selected)
    chosen[field] = True
    with pytest.raises(TimeCoverageError, match="boundary"):
        run(chosen, rows)


def test_rejects_unrecognized_selection_contract(selected, rows) -> None:
    selected["schema_id"] = "other"
    with pytest.raises(TimeCoverageError, match="selection contract"):
        run(selected, rows)


def test_rejects_unapproved_selection_status(selected, rows) -> None:
    selected["status"] = "joined"
    with pytest.raises(TimeCoverageError, match="no-join"):
        run(selected, rows)


@pytest.mark.parametrize("source", ["kev", "epss"])
def test_rejects_future_selected_date(selected, rows, source) -> None:
    selected[source]["source_date"] = "2026-01-16"
    with pytest.raises(TimeCoverageError, match="selected date"):
        run(selected, rows)


@pytest.mark.parametrize("source", ["kev", "epss"])
def test_rejects_future_retrieval(selected, rows, source) -> None:
    selected[source]["retrieved_at_utc"] = "2026-01-16T00:00:00Z"
    with pytest.raises(TimeCoverageError, match="retrieved after"):
        run(selected, rows)


def test_rejects_missing_retrieval_timezone(selected, rows) -> None:
    selected["epss"]["retrieved_at_utc"] = "2026-01-15T12:30:00"
    with pytest.raises(TimeCoverageError, match="explicit UTC offset"):
        run(selected, rows)


def test_normalizes_aware_timestamp_to_utc_calendar_day(selected, rows) -> None:
    selected["epss"]["retrieved_at_utc"] = "2026-01-15T23:30:00-02:00"
    with pytest.raises(TimeCoverageError, match="retrieved after"):
        run(selected, rows)


def test_rejects_nvd_future_publication(selected, rows) -> None:
    nvd = [(QID, "CVE-2025-0001", "2026-01-16T00:00:00.000", rows[0][0][3])]
    with pytest.raises(TimeCoverageError, match="published is after"):
        run(selected, (nvd, rows[1]))


def test_rejects_nvd_future_modification(selected, rows) -> None:
    nvd = [(QID, "CVE-2025-0001", rows[0][0][2], "2026-01-16T00:00:00.000")]
    with pytest.raises(TimeCoverageError, match="modified is after"):
        run(selected, (nvd, rows[1]))


def test_rejects_missing_nvd_timestamp(selected, rows) -> None:
    nvd = [(QID, "CVE-2025-0001", None, rows[0][0][3])]
    with pytest.raises(TimeCoverageError, match="complete ISO timestamp"):
        run(selected, (nvd, rows[1]))


def test_rejects_future_kev_added_date(selected, rows) -> None:
    with pytest.raises(TimeCoverageError, match="date_added is after"):
        run(selected, (rows[0], [(KEV_ID, "CVE-2025-0001", date(2026, 1, 16))]))


def test_rejects_partial_nvd_claimed_complete(selected, rows) -> None:
    selected["nvd"]["source_scope_flags"]["global_nvd_completeness_attested"] = True
    with pytest.raises(TimeCoverageError, match="global coverage"):
        run(selected, rows)


def test_rejects_nvd_count_mismatch(selected, rows) -> None:
    selected["nvd"]["cve_count"] = 3
    with pytest.raises(TimeCoverageError, match="count changed"):
        run(selected, rows)


def test_rejects_kev_count_mismatch(selected, rows) -> None:
    selected["kev"]["row_count"] = 2
    with pytest.raises(TimeCoverageError, match="count changed"):
        run(selected, rows)


def test_rejects_changed_query_identity(selected, rows) -> None:
    nvd = [("c" * 64, *rows[0][0][1:])]
    with pytest.raises(TimeCoverageError, match="query identity"):
        run(selected, (nvd, rows[1]))


def test_rejects_duplicate_nvd_rows(selected, rows) -> None:
    selected["nvd"]["cve_count"] = 2
    with pytest.raises(TimeCoverageError, match="Duplicate NVD"):
        run(selected, (rows[0] * 2, rows[1]))


@pytest.fixture
def databases(tmp_path: Path) -> tuple[Path, Path]:
    analytics = tmp_path / "analytics.duckdb"
    nvd = tmp_path / "nvd.duckdb"
    create_fixture(analytics)
    with duckdb.connect(str(nvd)) as con:
        _ddl(con)
        con.execute("INSERT INTO nvd_stage.query_registry VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            "patchline.nvd-duckdb-query-staging.v1", QID, "b" * 64, "c" * 64,
            "NVD_CVE", "last_modified_window", 1, 0, 1,
            False, False, False, False,
        ])
        con.execute("INSERT INTO nvd_stage.cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            QID, 0, "CVE-2025-0001", "example", "Analyzed",
            "2026-01-10T00:00:00.000", "2026-01-12T00:00:00.000",
            "Synthetic NVD item", "d" * 64, 0, 0,
            False, True, True, True, True, "{}",
        ])
    return analytics, nvd


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(databases, *, cutoff="2026-01-15", ack=True):
    return inspect_time_coverage(
        analytics_database=databases[0], nvd_database=databases[1],
        cutoff_date=cutoff, acknowledge_bounded_nvd=ack,
    )


def test_integrated_read_only_synthetic_preflight(databases) -> None:
    hashes = [digest(x) for x in databases]
    result = inspect(databases)
    assert result["nvd"]["checked_rows"] == 1
    assert result["kev"]["checked_rows"] == 3
    assert result["epss"]["selected_row_count"] == 4
    assert [digest(x) for x in databases] == hashes


def test_integrated_rejects_future_nvd_modified(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.cves SET modified_source_timestamp=?",
                    ["2026-01-16T00:00:00.000"])
    with pytest.raises(TimeCoverageError, match="modified is after"):
        inspect(databases)


def test_integrated_rejects_future_kev_date_added(databases) -> None:
    with duckdb.connect(str(databases[0])) as con:
        con.execute("UPDATE main.raw_kev_snapshot SET date_added=?", ["2026-01-16"])
    with pytest.raises(TimeCoverageError, match="date_added is after"):
        inspect(databases)


def test_integrated_rejects_invalid_nvd_date(databases) -> None:
    with duckdb.connect(str(databases[1])) as con:
        con.execute("UPDATE nvd_stage.cves SET published_source_timestamp=''")
    with pytest.raises(TimeCoverageError, match="complete ISO timestamp"):
        inspect(databases)


def test_integrated_cli_requires_explicit_ack(databases, capsys) -> None:
    args = ["--analytics-db", str(databases[0]), "--nvd-db", str(databases[1]),
            "--cutoff-date", "2026-01-15"]
    assert main(args) == 1
    assert '"status": "failed"' in capsys.readouterr().err
    assert main([*args, "--acknowledge-bounded-nvd"]) == 0
    assert '"join_approved": false' in capsys.readouterr().out
