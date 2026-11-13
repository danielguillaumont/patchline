"""EA-03A4E1: isolated synthetic contract and reconciliation tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from patchline.exports.cve_contract import (
    CANDIDATE_STATUS,
    CONTRACT_ID,
    JOIN_ID,
    CVEContractError,
    inspect_candidate,
    validate_candidate,
)


def example() -> tuple[dict, dict]:
    sid = {
        "nvd_query_id": "a" * 64,
        "nvd_query_mode": "last_modified_window",
        "kev_snapshot_id": "b" * 64,
        "kev_source_date": "2026-01-11",
        "epss_snapshot_id": "c" * 64,
        "epss_score_date": "2026-01-12",
        "epss_model_version": "v-ci-synthetic",
    }
    metric = {
        "metric_index": 0, "metric_key": "cvssMetricV31", "cvss_version": "3.1",
        "metric_source": "synthetic", "metric_type": "Primary", "vector_string": None,
        "base_score": 9.8, "base_severity": "CRITICAL",
    }
    records = [
        {
            "cve_id": "CVE-2099-0001",
            "nvd": {
                "query_id": "a" * 64, "vuln_status": "Analyzed",
                "published_source_timestamp": "2026-01-10T00:00:00.000",
                "modified_source_timestamp": "2026-01-11T00:00:00.000",
                "source_page_sha256": "d" * 64, "cvss_metrics": [metric],
            },
            "kev": {"listed_in_selected_snapshot": True, "date_added": "2026-01-11"},
            "epss": {"has_score_in_selected_snapshot": True, "score": 0.0,
                     "percentile": 0.0},
        },
        {
            "cve_id": "CVE-2099-0002",
            "nvd": {
                "query_id": "a" * 64, "vuln_status": "Awaiting Analysis",
                "published_source_timestamp": "2026-01-10T00:00:00.000",
                "modified_source_timestamp": "2026-01-12T00:00:00.000",
                "source_page_sha256": "d" * 64, "cvss_metrics": [],
            },
            "kev": {"listed_in_selected_snapshot": False, "date_added": None},
            "epss": {"has_score_in_selected_snapshot": False, "score": None,
                     "percentile": None},
        },
    ]
    coverage = {
        "nvd_query_cves": 2, "in_selected_kev_snapshot": 1,
        "with_selected_epss_score": 1, "nvd_cvss_metric_rows": 1,
        "missing_nvd_cves_outside_query_are_unknown": True,
    }
    source = {
        "schema_id": JOIN_ID, "status": "local_bounded_nvd_cve_join_executed",
        "cross_source_join_executed": True,
        "data_kind": "source_scoped_local_analysis",
        "row_scope": "only_cves_returned_by_one_bounded_nvd_query",
        "analysis_cutoff_date": "2026-01-15",
        "time_precision": "calendar_date_guard_only_not_as_of_reconstruction",
        "selection_contract": "exploit-atlas.cross-source-selection.v1",
        "time_coverage_contract": "exploit-atlas.time-coverage-preflight.v1",
        "source_ids": sid, "coverage": coverage, "records": records,
        "historical_as_of_reconstruction_attested": False,
        "nvd_global_coverage_attested": False,
        "organization_asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
        "published_to_public_demo": False,
    }
    candidate = {k: deepcopy(source[k]) for k in (
        "data_kind", "row_scope", "analysis_cutoff_date", "time_precision",
        "selection_contract", "time_coverage_contract", "source_ids", "coverage",
        "records", "historical_as_of_reconstruction_attested",
        "nvd_global_coverage_attested", "organization_asset_exposure_known",
        "source_archive_reverified_by_this_command", "published_to_public_demo",
    )}
    candidate.update({"schema_id": CONTRACT_ID, "status": CANDIDATE_STATUS,
                      "source_join_schema_id": JOIN_ID})
    return source, candidate


def reject(candidate: dict, source: dict, part: str) -> None:
    with pytest.raises(CVEContractError, match=part):
        validate_candidate(candidate, bounded_join=source)


def test_approved_shape_is_only_local_candidate() -> None:
    source, candidate = example()
    result = inspect_candidate(candidate, bounded_join=source)
    assert result == {
        "schema_id": CONTRACT_ID,
        "status": "candidate_contract_validated_not_published",
        "records_checked": 2, "nvd_query_id": "a" * 64,
        "public_release_approved": False,
    }
    assert candidate["records"][0]["epss"]["score"] == 0.0
    assert candidate["records"][1]["epss"]["score"] is None


def test_reject_missing_schema_and_unknown_field() -> None:
    source, candidate = example()
    del candidate["source_ids"]
    reject(candidate, source, "schema")
    source, candidate = example()
    candidate["risk_score"] = 0.99
    reject(candidate, source, "schema")


def test_reject_publication_or_global_claims() -> None:
    for field in ("published_to_public_demo", "nvd_global_coverage_attested",
                  "historical_as_of_reconstruction_attested"):
        source, candidate = example()
        candidate[field] = True
        reject(candidate, source, "schema")


def test_reject_foreign_query_snapshot_and_dates() -> None:
    for key, new_value in (("nvd_query_id", "e" * 64),
                           ("kev_source_date", "2026-01-10"),
                           ("epss_model_version", "other")):
        source, candidate = example()
        candidate["source_ids"][key] = new_value
        reject(candidate, source, "source IDs or dates")


def test_reject_missing_score_imputed_zero() -> None:
    source, candidate = example()
    candidate["records"][1]["epss"]["score"] = 0.0
    reject(candidate, source, "records differ")


def test_reject_dropped_and_inserted_cve() -> None:
    source, candidate = example()
    candidate["records"].pop()
    reject(candidate, source, "records differ")
    source, candidate = example()
    candidate["records"].append(deepcopy(candidate["records"][0]))
    reject(candidate, source, "records differ")


def test_reject_modified_metric_source_and_order() -> None:
    source, candidate = example()
    candidate["records"][0]["nvd"]["cvss_metrics"][0]["metric_source"] = "invented"
    reject(candidate, source, "records differ")
    source, candidate = example()
    candidate["records"].reverse()
    reject(candidate, source, "records differ")


def test_reject_changed_coverage() -> None:
    source, candidate = example()
    candidate["coverage"]["in_selected_kev_snapshot"] = 2
    reject(candidate, source, "coverage differs")


def test_reject_wrong_report_identity() -> None:
    source, candidate = example()
    source["schema_id"] = "another.contract.v1"
    reject(candidate, source, "Unexpected source join contract")


def test_reject_invalid_source_report_coverage() -> None:
    source, candidate = example()
    source["coverage"]["with_selected_epss_score"] = 2
    reject(candidate, source, "EPSS coverage count")


def test_reject_source_report_false_global_attestation() -> None:
    source, candidate = example()
    source["nvd_global_coverage_attested"] = True
    reject(candidate, source, "Source join attestation unsafe")


def test_reject_nan_and_infinity() -> None:
    for value in (float("nan"), float("inf"), -float("inf")):
        source, candidate = example()
        candidate["records"][0]["epss"]["score"] = value
        reject(candidate, source, "finite JSON")


def test_reject_unsupported_cvss_and_risk() -> None:
    source, candidate = example()
    candidate["records"][0]["nvd"]["cvss_metrics"][0]["cvss_version"] = "5.0"
    reject(candidate, source, "schema")
    source, candidate = example()
    candidate["records"][0]["nvd"]["cvss_metrics"][0]["composite_risk_score"] = 99
    reject(candidate, source, "schema")


def test_reject_non_boolean_membership() -> None:
    source, candidate = example()
    candidate["records"][0]["kev"]["listed_in_selected_snapshot"] = 1
    reject(candidate, source, "schema")


def test_reject_forged_source_report_missing_score() -> None:
    source, candidate = example()
    source["records"][1]["epss"]["score"] = 0.0
    reject(candidate, source, "EPSS missing values")


def test_reject_malformed_source_join_metric_index() -> None:
    source, candidate = example()
    source["records"][0]["nvd"]["cvss_metrics"][0]["metric_index"] = 7
    reject(candidate, source, "CVSS metric order")


def test_empty_bounded_query_is_accepted_without_absence_claim() -> None:
    source, candidate = example()
    for payload in (source, candidate):
        payload["records"] = []
        payload["coverage"] = {
            "nvd_query_cves": 0, "in_selected_kev_snapshot": 0,
            "with_selected_epss_score": 0, "nvd_cvss_metric_rows": 0,
            "missing_nvd_cves_outside_query_are_unknown": True,
        }
    validate_candidate(candidate, bounded_join=source)


def test_reject_source_join_query_id_inconsistent_with_lineage() -> None:
    source, candidate = example()
    source["records"][0]["nvd"]["query_id"] = "f" * 64
    candidate["records"][0]["nvd"]["query_id"] = "f" * 64
    reject(candidate, source, "Per-CVE NVD query identity")
