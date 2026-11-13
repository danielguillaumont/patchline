"""EA-03A4D1: read-only date and bounded-coverage guard, NOT a CVE-level join.

Calendar-date checks are deliberately weaker than historical point-in-time proofs.
No as-of reconstruction, absence claims, publication, or join is approved here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

POLICY_VERSION = "exploit-atlas.time-coverage-preflight.v1"
SELECTION_VERSION = "exploit-atlas.cross-source-selection.v1"
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class TimeCoverageError(ValueError):
    """Reject a selection that exceeds known temporal or coverage boundaries."""


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise TimeCoverageError(message)


def _day(value: Any, label: str) -> date:
    _require(isinstance(value, str) and len(value) == 10,
             f"{label} must be an ISO calendar date (YYYY-MM-DD)")
    try:
        day = date.fromisoformat(value)
    except ValueError as exc:
        raise TimeCoverageError(f"{label} must be an ISO calendar date") from exc
    _require(day.isoformat() == value, f"{label} must be a canonical ISO date")
    return day


def _timestamp_day(value: Any, label: str, *, require_zone: bool) -> date:
    """Interpret UTC-aware timestamps in UTC, and NVD naive timestamps by calendar date.

    NVD normalized timestamps lack timezone attestation; this intentionally does
    not claim instant-level precision or historical source availability.
    """
    _require(isinstance(value, str) and "T" in value and len(value) >= 19,
             f"{label} must be a complete ISO timestamp")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimeCoverageError(f"{label} has an invalid timestamp") from exc
    if require_zone:
        _require(instant.tzinfo is not None and instant.utcoffset() is not None,
                 f"{label} must contain an explicit UTC offset")
    if instant.tzinfo is not None:
        instant = instant.astimezone(UTC)
    return instant.date()


def validate_time_coverage(
    selection: Mapping[str, Any], *, cutoff_date: str,
    acknowledge_bounded_nvd: bool,
    nvd_cves: Sequence[tuple[Any, Any, Any, Any]],
    kev_records: Sequence[tuple[Any, Any, Any]],
) -> dict[str, Any]:
    """Evaluate one already validated selection, without joining CVE populations.

    nvd_cves: (query_id, cve_id, published, modified)
    kev_records: (snapshot_id, cve_id, date_added)
    """
    cutoff = _day(cutoff_date, "analysis cutoff")
    _require(acknowledge_bounded_nvd is True,
             "Explicit acknowledgement of bounded NVD query coverage required")
    _require(isinstance(selection, Mapping), "Source selection is missing")
    _require(selection.get("schema_id") == SELECTION_VERSION,
             "Unexpected cross-source selection contract")
    _require(selection.get("status") == "source_selection_validated_no_join",
             "Source selection has not passed the no-join preflight")
    for flag in ("cross_source_join_executed", "join_approved",
                 "point_in_time_alignment_attested", "nvd_global_coverage_attested",
                 "asset_exposure_known", "source_archive_reverified_by_this_command"):
        _require(selection.get(flag) is False,
                 f"Source selection boundary violated: {flag}")

    kev = selection.get("kev")
    epss = selection.get("epss")
    nvd = selection.get("nvd")
    _require(isinstance(kev, Mapping) and isinstance(epss, Mapping)
             and isinstance(nvd, Mapping), "Selected source metadata missing")
    for label, source in (("KEV", kev), ("EPSS", epss)):
        source_day = _day(source.get("source_date"), f"{label} selected date")
        _require(source_day <= cutoff, f"{label} selected date is after analysis cutoff")
        retrieved_day = _timestamp_day(source.get("retrieved_at_utc"),
                                       f"{label} retrieved_at_utc", require_zone=True)
        _require(retrieved_day <= cutoff,
                 f"{label} retrieved after analysis cutoff")
        _require(isinstance(source.get("snapshot_id"), str)
                 and SHA256.fullmatch(source["snapshot_id"]) is not None,
                 f"{label} selected snapshot ID is invalid")
        _require(type(source.get("row_count")) is int and source["row_count"] >= 0,
                 f"{label} selected row count is invalid")

    _require(isinstance(nvd.get("query_id"), str)
             and SHA256.fullmatch(nvd["query_id"]) is not None,
             "NVD selected query ID is invalid")
    _require(nvd.get("source") == "NVD_CVE", "Unexpected NVD source")
    _require(isinstance(nvd.get("query_mode"), str)
             and bool(nvd["query_mode"].strip()), "NVD query mode missing")
    flags = nvd.get("source_scope_flags")
    _require(isinstance(flags, Mapping) and set(flags) == {
        "point_in_time_consistency_verified", "global_nvd_completeness_attested",
        "source_origin_independently_verified", "organization_asset_exposure_known",
    } and all(v is False for v in flags.values()),
             "Bounded NVD query cannot attest global coverage or exposure")
    _require(type(nvd.get("cve_count")) is int and nvd["cve_count"] >= 0,
             "NVD selected row count invalid")
    _require(len(nvd_cves) == nvd["cve_count"],
             "NVD record count changed after source selection")
    _require(len(kev_records) == kev["row_count"],
             "KEV record count changed after source selection")

    nvd_seen: set[str] = set()
    for query_id, cve, published, modified in nvd_cves:
        _require(query_id == nvd["query_id"], "NVD row query identity changed")
        _require(isinstance(cve, str) and CVE_ID.fullmatch(cve) is not None,
                 "NVD CVE identifier invalid")
        _require(cve not in nvd_seen, "Duplicate NVD CVE in temporal read")
        nvd_seen.add(cve)
        for column, value in (("published", published), ("modified", modified)):
            row_day = _timestamp_day(value, f"NVD {cve} {column}", require_zone=False)
            _require(row_day <= cutoff,
                     f"NVD {cve} {column} is after analysis cutoff")

    kev_seen: set[str] = set()
    for snapshot_id, cve, added in kev_records:
        _require(snapshot_id == kev["snapshot_id"],
                 "KEV row snapshot identity changed")
        _require(isinstance(cve, str) and CVE_ID.fullmatch(cve) is not None,
                 "KEV CVE identifier invalid")
        _require(cve not in kev_seen, "Duplicate KEV CVE in temporal read")
        kev_seen.add(cve)
        # DuckDB DATE values are Python dates. Explicitly refuse timestamps.
        _require(type(added) is date, f"KEV {cve} date_added is not a DATE")
        _require(added <= cutoff, f"KEV {cve} date_added is after analysis cutoff")

    return {
        "schema_id": POLICY_VERSION,
        "status": "bounded_source_temporal_preflight_passed_no_join",
        "analysis_cutoff_date": cutoff.isoformat(),
        "temporal_precision": "calendar_date_only",
        "selection_contract": SELECTION_VERSION,
        "kev": {"snapshot_id": kev["snapshot_id"], "selected_date": kev["source_date"],
                "checked_rows": len(kev_records)},
        "epss": {"snapshot_id": epss["snapshot_id"], "selected_date": epss["source_date"],
                 "selected_row_count": epss["row_count"]},
        "nvd": {"query_id": nvd["query_id"], "query_mode": nvd["query_mode"],
                "checked_rows": len(nvd_cves), "coverage": "bounded_query_only",
                "absence_in_query_proves_not_vulnerable": False},
        "bounded_nvd_acknowledged": True,
        "cross_source_join_executed": False,
        "join_approved": False,
        "historical_as_of_reconstruction_attested": False,
        "nvd_global_coverage_attested": False,
        "nvd_acquisition_time_verified": False,
        "organization_asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
        "interpretation": (
            "Only calendar-date and bounded-coverage preflight checks passed. "
            "NVD source acquisition time and coherent as-of state are not attested. "
            "A bounded query cannot establish absence outside its returned rows. "
            "No CVE join, historical reconstruction, risk score or publication is approved."
        ),
    }


def inspect_time_coverage(*, analytics_database: Path, nvd_database: Path,
                          cutoff_date: str, acknowledge_bounded_nvd: bool) -> dict[str, Any]:
    """Re-run EA-03A4C, then read each existing source database read-only."""
    # Validate inputs before opening source files.
    _day(cutoff_date, "analysis cutoff")
    _require(acknowledge_bounded_nvd is True,
             "Explicit acknowledgement of bounded NVD query coverage required")

    import duckdb

    from patchline.warehouse.cross_source_contract import (
        SourceContractError,
        inspect_source_selection,
    )

    try:
        selection = inspect_source_selection(
            analytics_database=analytics_database, nvd_database=nvd_database
        )
        # The preflight already rejects symlinks and same-file input; reopen read-only.
        with duckdb.connect(str(analytics_database), read_only=True) as con:
            kev_rows = con.execute(
                "SELECT snapshot_id, cve_id, date_added FROM main.raw_kev_snapshot"
            ).fetchall()
        with duckdb.connect(str(nvd_database), read_only=True) as con:
            nvd_rows = con.execute(
                """SELECT query_id, cve_id, published_source_timestamp,
                          modified_source_timestamp FROM nvd_stage.cves"""
            ).fetchall()
    except (duckdb.Error, SourceContractError, OSError) as exc:
        raise TimeCoverageError(f"Read-only source preflight failed: {exc}") from exc
    return validate_time_coverage(
        selection, cutoff_date=cutoff_date,
        acknowledge_bounded_nvd=acknowledge_bounded_nvd,
        nvd_cves=nvd_rows, kev_records=kev_rows,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analytics-db", type=Path, required=True)
    parser.add_argument("--nvd-db", type=Path, required=True)
    parser.add_argument("--cutoff-date", required=True,
                        help="YYYY-MM-DD; calendar-date safeguard, NOT historical as-of")
    parser.add_argument("--acknowledge-bounded-nvd", action="store_true",
                        help="NVD records represent only a bounded query, not global coverage")
    args = parser.parse_args(argv)
    try:
        result = inspect_time_coverage(
            analytics_database=args.analytics_db,
            nvd_database=args.nvd_db,
            cutoff_date=args.cutoff_date,
            acknowledge_bounded_nvd=args.acknowledge_bounded_nvd,
        )
    except (TimeCoverageError, OSError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, sort_keys=True),
              file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
