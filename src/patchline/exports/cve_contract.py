"""EA-03A4E1: validate a proposed local CVE consumer payload, never publish it.

This is a boundary validator, NOT an export generator or authorization to publish.
It reconciles a candidate against one previously validated bounded-join report.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

CONTRACT_ID = "exploit-atlas.cve-consumer-candidate.v1"
JOIN_ID = "exploit-atlas.bounded-cve-join.v1"
CANDIDATE_STATUS = "local_candidate_not_approved_for_publication"
SCOPE = "only_cves_returned_by_one_bounded_nvd_query"
DISALLOWED_ATTESTATIONS = (
    "historical_as_of_reconstruction_attested",
    "nvd_global_coverage_attested",
    "organization_asset_exposure_known",
    "source_archive_reverified_by_this_command",
    "published_to_public_demo",
)


class CVEContractError(ValueError):
    """An in-memory candidate does not satisfy the bounded consumer contract."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise CVEContractError(reason)


@lru_cache(maxsize=1)
def _schema_validator() -> Draft202012Validator:
    file = Path(__file__).parent / "contracts" / "cve_consumer_candidate.v1.schema.json"
    schema = json.loads(file.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _strict_json(value: object, label: str) -> None:
    try:
        json.dumps(value, allow_nan=False)
    except (ValueError, TypeError, OverflowError) as exc:
        raise CVEContractError(f"{label}: not a finite JSON document") from exc


def _validate_shape(candidate: Mapping[str, Any]) -> None:
    errors = sorted(
        _schema_validator().iter_errors(candidate),
        key=lambda error: (tuple(str(v) for v in error.absolute_path), error.message),
    )
    if errors:
        first = errors[0]
        path = ".".join(map(str, first.absolute_path)) or "root"
        raise CVEContractError(f"Consumer schema rejected {path}: {first.message}")


def _check_source_report(report: Mapping[str, Any]) -> None:
    _require(report.get("schema_id") == JOIN_ID, "Unexpected source join contract")
    _require(report.get("status") == "local_bounded_nvd_cve_join_executed",
             "Source join is not an executed bounded report")
    _require(report.get("cross_source_join_executed") is True,
             "Source join execution flag is missing")
    _require(report.get("row_scope") == SCOPE, "Source join scope is not bounded")
    _require(report.get("data_kind") == "source_scoped_local_analysis",
             "Unexpected source join data classification")
    _require(report.get("time_precision") == "calendar_date_guard_only_not_as_of_reconstruction",
             "Unexpected temporal precision")
    for flag in DISALLOWED_ATTESTATIONS:
        _require(report.get(flag) is False, f"Source join attestation unsafe: {flag}")
    _require(isinstance(report.get("records"), list), "Source join records missing")
    _require(isinstance(report.get("source_ids"), dict), "Source join provenance missing")
    _require(isinstance(report.get("coverage"), dict), "Source join coverage missing")
    source_records = report["records"]
    _require(all(isinstance(row, Mapping) for row in source_records),
             "Source join record is not an object")
    ids = [r.get("cve_id") for r in source_records]
    _require(all(isinstance(cve, str) for cve in ids), "Source join CVE identifier missing")
    _require(ids == sorted(set(ids)), "Source join CVEs are not uniquely sorted")
    _check_coverage(source_records, report["coverage"])


def _check_coverage(records: list[Mapping[str, Any]], coverage: Mapping[str, Any]) -> None:
    try:
        _require(coverage.get("missing_nvd_cves_outside_query_are_unknown") is True,
                 "Bounded NVD absence disclaimer missing")
        _require(coverage.get("nvd_query_cves") == len(records),
                 "NVD record coverage does not reconcile")
        kev = 0
        epss = 0
        metrics = 0
        for row in records:
            listed = row["kev"]["listed_in_selected_snapshot"]
            scored = row["epss"]["has_score_in_selected_snapshot"]
            _require(type(listed) is bool and type(scored) is bool,
                     "KEV/EPSS presence must be boolean")
            _require((row["kev"]["date_added"] is not None) == listed,
                     "KEV missing/present date does not reconcile")
            _require((row["epss"]["score"] is not None) == scored
                     and (row["epss"]["percentile"] is not None) == scored,
                     "EPSS missing values must be null; real zero remains zero")
            if scored:
                for field in ("score", "percentile"):
                    value = row["epss"][field]
                    _require(type(value) in (int, float) and math.isfinite(value)
                             and 0 <= value <= 1, "Invalid EPSS probability")
            metric_rows = row["nvd"]["cvss_metrics"]
            _require(isinstance(metric_rows, list), "CVSS metrics must be an array")
            _require([m["metric_index"] for m in metric_rows] == list(range(len(metric_rows))),
                     "CVSS metric order/index does not reconcile")
            metrics += len(metric_rows)
            kev += int(listed)
            epss += int(scored)
        _require(coverage.get("in_selected_kev_snapshot") == kev,
                 "KEV overlap count does not reconcile")
        _require(coverage.get("with_selected_epss_score") == epss,
                 "EPSS coverage count does not reconcile")
        _require(coverage.get("nvd_cvss_metric_rows") == metrics,
                 "CVSS metric count does not reconcile")
    except (KeyError, TypeError, IndexError) as exc:
        raise CVEContractError("Malformed CVE record or coverage structure") from exc


def validate_candidate(candidate: Mapping[str, Any], *, bounded_join: Mapping[str, Any]) -> None:
    """Reject unapproved or distorted consumer candidates before any later export.

    Does not verify upstream archives or establish historical as-of coherence.
    Requires the precise original bounded-join records as reconciliation reference.
    """
    _require(isinstance(candidate, Mapping), "Consumer candidate must be an object")
    _require(isinstance(bounded_join, Mapping), "Bounded join must be an object")
    _strict_json(candidate, "Consumer candidate")
    _strict_json(bounded_join, "Bounded join")
    _validate_shape(candidate)
    _check_source_report(bounded_join)

    _require(candidate["source_join_schema_id"] == JOIN_ID,
             "Candidate must reference the bounded join contract")
    _require(candidate["source_ids"] == bounded_join["source_ids"],
             "Candidate source IDs or dates differ from selected sources")
    _require(candidate["selection_contract"] == bounded_join["selection_contract"],
             "Source selection contract differs")
    _require(candidate["time_coverage_contract"] == bounded_join["time_coverage_contract"],
             "Time coverage contract differs")
    _require(candidate["analysis_cutoff_date"] == bounded_join["analysis_cutoff_date"],
             "Analysis cutoff differs")
    _require(candidate["coverage"] == bounded_join["coverage"],
             "Candidate coverage differs from bounded join")
    _require(candidate["records"] == bounded_join["records"],
             "Candidate CVE records differ from selected bounded join")
    _require(all(row["nvd"]["query_id"] == candidate["source_ids"]["nvd_query_id"]
                 for row in candidate["records"]),
             "Per-CVE NVD query identity differs from selected query")
    for flag in DISALLOWED_ATTESTATIONS:
        _require(candidate[flag] is False, f"Candidate cannot attest: {flag}")
    _check_coverage(candidate["records"], candidate["coverage"])


def inspect_candidate(candidate: Mapping[str, Any], *, bounded_join: Mapping[str, Any]) -> dict[str, Any]:
    """Return only validation metadata; never create or publish any artifact."""
    validate_candidate(candidate, bounded_join=bounded_join)
    return {
        "schema_id": CONTRACT_ID,
        "status": "candidate_contract_validated_not_published",
        "records_checked": len(candidate["records"]),
        "nvd_query_id": candidate["source_ids"]["nvd_query_id"],
        "public_release_approved": False,
    }
