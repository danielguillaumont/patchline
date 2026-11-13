"""EA-03A4D2: synthetic bounded-query CVE overlaps and negative tests."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import date
from pathlib import Path

import pytest

from patchline.warehouse.cross_source_join import (
    JOIN_VERSION,
    BoundedJoinError,
    build_bounded_join,
    main,
    save_local_no_replace,
)

QID = "a" * 64
KEV_ID = hashlib.sha256(b"patchline-ci-synthetic-kev-v1").hexdigest()
EPSS_ID = hashlib.sha256(b"patchline-ci-synthetic-epss-v1").hexdigest()


@pytest.fixture
def selected() -> dict:
    return {
        "schema_id": "exploit-atlas.cross-source-selection.v1",
        "status": "source_selection_validated_no_join",
        "kev": {"snapshot_id": KEV_ID, "source_date": "2026-01-15",
                "retrieved_at_utc": "2026-01-15T12:00:00Z", "row_count": 2},
        "epss": {"snapshot_id": EPSS_ID, "source_date": "2026-01-15",
                 "retrieved_at_utc": "2026-01-15T12:30:00Z", "row_count": 2,
                 "model_version": "v-ci-synthetic"},
        "nvd": {"query_id": QID, "query_mode": "last_modified_window",
                "source": "NVD_CVE", "cve_count": 3, "cvss_metric_count": 2,
                "source_scope_flags": {
                    "point_in_time_consistency_verified": False,
                    "global_nvd_completeness_attested": False,
                    "source_origin_independently_verified": False,
                    "organization_asset_exposure_known": False,
                }},
        "cross_source_join_executed": False,
        "join_approved": False,
        "point_in_time_alignment_attested": False,
        "nvd_global_coverage_attested": False,
        "asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
    }


@pytest.fixture
def rows() -> dict:
    nvd = [
        (QID, "CVE-2099-0001", "2026-01-01T00:00:00.000",
         "2026-01-12T00:00:00.000", "Analyzed", "d" * 64),
        (QID, "CVE-2099-0003", "2026-01-01T00:00:00.000",
         "2026-01-12T00:00:00.000", "Analyzed", "d" * 64),
        (QID, "CVE-2099-9999", "2026-01-01T00:00:00.000",
         "2026-01-12T00:00:00.000", "Awaiting Analysis", "d" * 64),
    ]
    metrics = [
        (QID, "CVE-2099-0001", 0, "cvssMetricV31", "3.1", "NVD", "Primary",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
        (QID, "CVE-2099-0001", 1, "cvssMetricV40", "4.0", "NVD", "Secondary",
         None, None, None),
    ]
    return {
        "kev_rows": [
            (KEV_ID, "CVE-2099-0001", date(2026, 1, 10)),
            (KEV_ID, "CVE-2099-0003", date(2026, 1, 11)),
        ],
        "epss_rows": [
            (EPSS_ID, "CVE-2099-0001", date(2026, 1, 15), "v-ci-synthetic", 0.0, 0.0),
            (EPSS_ID, "CVE-2099-9001", date(2026, 1, 15), "v-ci-synthetic", 0.8, 0.9),
        ],
        "nvd_rows": nvd,
        "metric_rows": metrics,
    }


def run(selected, rows, *, cutoff="2026-01-15", ack=True):
    return build_bounded_join(selected, cutoff_date=cutoff,
                              acknowledge_bounded_nvd=ack, **rows)


def test_bounded_query_only_and_missing_semantics(selected, rows) -> None:
    result = run(selected, rows)
    assert result["schema_id"] == JOIN_VERSION
    assert result["cross_source_join_executed"] is True
    assert result["historical_as_of_reconstruction_attested"] is False
    assert result["published_to_public_demo"] is False
    assert result["coverage"] == {
        "nvd_query_cves": 3, "in_selected_kev_snapshot": 2,
        "with_selected_epss_score": 1, "nvd_cvss_metric_rows": 2,
        "missing_nvd_cves_outside_query_are_unknown": True,
    }
    r1, r3, r9 = result["records"]
    assert [r["cve_id"] for r in result["records"]] == [
        "CVE-2099-0001", "CVE-2099-0003", "CVE-2099-9999"
    ]
    assert r1["epss"]["has_score_in_selected_snapshot"] is True
    assert r1["epss"]["score"] == 0.0  # True zero, NOT missing.
    assert [metric["cvss_version"] for metric in r1["nvd"]["cvss_metrics"]] == ["3.1", "4.0"]
    assert r1["nvd"]["cvss_metrics"][1]["base_score"] is None
    assert r3["kev"]["listed_in_selected_snapshot"] is True
    assert r3["epss"]["score"] is None
    assert r9["kev"]["listed_in_selected_snapshot"] is False
    assert r9["epss"]["score"] is None
    assert "CVE-2099-9001" not in [r["cve_id"] for r in result["records"]]
    json.dumps(result, allow_nan=False)


def test_requires_bounded_ack(selected, rows) -> None:
    with pytest.raises(BoundedJoinError, match="acknowledgement"):
        run(selected, rows, ack=False)


def test_rejects_future_modified_nvd(selected, rows) -> None:
    rows["nvd_rows"][0] = (*rows["nvd_rows"][0][:3], "2026-01-16T00:00:00.000",
                            *rows["nvd_rows"][0][4:])
    with pytest.raises(BoundedJoinError, match="modified is after"):
        run(selected, rows)


def test_rejects_future_kev_date_added(selected, rows) -> None:
    rows["kev_rows"][1] = (KEV_ID, "CVE-2099-0003", date(2026, 1, 16))
    with pytest.raises(BoundedJoinError, match="date_added is after"):
        run(selected, rows)


def test_rejects_false_global_coverage(selected, rows) -> None:
    selected["nvd"]["source_scope_flags"]["global_nvd_completeness_attested"] = True
    with pytest.raises(BoundedJoinError, match="global coverage"):
        run(selected, rows)


def test_rejects_nvd_query_identity_change(selected, rows) -> None:
    rows["nvd_rows"][0] = ("b" * 64, *rows["nvd_rows"][0][1:])
    with pytest.raises(BoundedJoinError, match="query identity"):
        run(selected, rows)


def test_rejects_wrong_ep_ss_model_version(selected, rows) -> None:
    row = rows["epss_rows"][0]
    rows["epss_rows"][0] = (*row[:3], "other", *row[4:])
    with pytest.raises(BoundedJoinError, match="model version"):
        run(selected, rows)


def test_rejects_changed_epss_population(selected, rows) -> None:
    rows["epss_rows"].pop()
    with pytest.raises(BoundedJoinError, match="population count"):
        run(selected, rows)


def test_rejects_duplicate_epss(selected, rows) -> None:
    rows["epss_rows"][1] = rows["epss_rows"][0]
    with pytest.raises(BoundedJoinError, match="duplicate"):
        run(selected, rows)


def test_rejects_invalid_ep_ss_probability(selected, rows) -> None:
    row = rows["epss_rows"][0]
    rows["epss_rows"][0] = (*row[:4], float("nan"), row[5])
    with pytest.raises(BoundedJoinError, match="score must"):
        run(selected, rows)


def test_rejects_unknown_cvss_version(selected, rows) -> None:
    row = rows["metric_rows"][0]
    rows["metric_rows"][0] = (*row[:4], "5.0", *row[5:])
    with pytest.raises(BoundedJoinError, match="CVSS version"):
        run(selected, rows)


def test_rejects_cvss_metric_missing_index(selected, rows) -> None:
    row = rows["metric_rows"][1]
    rows["metric_rows"][1] = (*row[:2], 2, *row[3:])
    with pytest.raises(BoundedJoinError, match="index gap"):
        run(selected, rows)


def test_rejects_metric_count_drift(selected, rows) -> None:
    selected["nvd"]["cvss_metric_count"] = 1
    with pytest.raises(BoundedJoinError, match="count changed"):
        run(selected, rows)


def test_prevents_output_overwrite_and_git_tree(selected, rows, tmp_path: Path) -> None:
    result = run(selected, rows)
    output = tmp_path / "bounded.json"
    save_local_no_replace(result, output=output, forbidden_inputs=())
    assert json.loads(output.read_text(encoding="utf-8"))["schema_id"] == JOIN_VERSION
    with pytest.raises(BoundedJoinError, match="refusing overwrite"):
        save_local_no_replace(result, output=output, forbidden_inputs=())
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    with pytest.raises(BoundedJoinError, match="Git working tree"):
        save_local_no_replace(result, output=repo / "joined.json", forbidden_inputs=())


def test_empty_query_has_no_inferred_absence(selected, rows) -> None:
    selected = deepcopy(selected)
    selected["nvd"]["cve_count"] = 0
    selected["nvd"]["cvss_metric_count"] = 0
    rows["nvd_rows"] = []
    rows["metric_rows"] = []
    result = run(selected, rows)
    assert result["records"] == []
    assert result["coverage"]["missing_nvd_cves_outside_query_are_unknown"] is True


def test_integrated_read_only_and_cli_opt_in(tmp_path: Path, capsys) -> None:
    duckdb = pytest.importorskip("duckdb")
    from patchline.fixtures.ci_warehouse import create_fixture
    from patchline.warehouse.nvd_stage import _ddl

    analytics = tmp_path / "analytics.duckdb"
    nvd_db = tmp_path / "nvd.duckdb"
    create_fixture(analytics)
    with duckdb.connect(str(nvd_db)) as con:
        _ddl(con)
        con.execute("INSERT INTO nvd_stage.query_registry VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            "patchline.nvd-duckdb-query-staging.v1", QID, "b" * 64, "c" * 64,
            "NVD_CVE", "last_modified_window", 3, 2, 1,
            False, False, False, False,
        ])
        for idx, cve in enumerate(("CVE-2099-0001", "CVE-2099-0003", "CVE-2099-9999")):
            con.execute("INSERT INTO nvd_stage.cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
                QID, idx, cve, "example", "Analyzed", "2026-01-10T00:00:00.000",
                "2026-01-12T00:00:00.000", "synthetic", "d" * 64, 0, idx,
                False, idx != 0, True, True, True, "{}",
            ])
        for idx, version in enumerate(("3.1", "4.0")):
            con.execute("INSERT INTO nvd_stage.cvss_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
                QID, "CVE-2099-0001", idx, f"cvssMetricV{version.replace('.', '')}",
                version, "test", "Primary", None, 9.8 if idx == 0 else None,
                "CRITICAL" if idx == 0 else None, "{}",
            ])
    original = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (analytics, nvd_db)]
    output = tmp_path / "local-only.json"
    base = ["--analytics-db", str(analytics), "--nvd-db", str(nvd_db),
            "--cutoff-date", "2026-01-15", "--output", str(output),
            "--acknowledge-bounded-nvd"]
    assert main(base) == 1
    assert "Explicit --execute-bounded-join" in capsys.readouterr().err
    assert main([*base, "--execute-bounded-join"]) == 0
    assert '"nvd_query_cves": 3' in capsys.readouterr().out
    assert [hashlib.sha256(p.read_bytes()).hexdigest() for p in (analytics, nvd_db)] == original
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert len(saved["records"]) == 3
    assert saved["coverage"]["with_selected_epss_score"] == 1
    assert main([*base, "--execute-bounded-join"]) == 1
    assert "refusing overwrite" in capsys.readouterr().err
