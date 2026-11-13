"""EA-03A4D2: explicit, local-only CVE overlap anchored to ONE bounded NVD query.

This is NOT a global NVD catalog, historical as-of reconstruction, risk score,
asset exposure inference, or an approved public consumer export.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

from patchline.warehouse.cross_source_policy import (
    TimeCoverageError,
    validate_time_coverage,
)

JOIN_VERSION = "exploit-atlas.bounded-cve-join.v1"
CVSS_VERSIONS = {"2.0", "3.0", "3.1", "4.0"}


class BoundedJoinError(ValueError):
    """The opt-in, source-scoped join was not safe to produce."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise BoundedJoinError(reason)


def _unique(items: Sequence[tuple[Any, ...]], key: int, label: str) -> dict[str, tuple[Any, ...]]:
    result: dict[str, tuple[Any, ...]] = {}
    for item in items:
        identifier = item[key]
        _require(isinstance(identifier, str), f"{label}: invalid CVE identity")
        _require(identifier not in result, f"{label}: duplicate CVE identity")
        result[identifier] = item
    return result


def _probability(value: Any, label: str) -> float:
    _require(type(value) in (float, int) and math.isfinite(value)
             and 0 <= value <= 1, f"{label}: score must be within [0, 1]")
    return float(value)


def build_bounded_join(
    selection: Mapping[str, Any], *, cutoff_date: str,
    acknowledge_bounded_nvd: bool,
    kev_rows: Sequence[tuple[Any, Any, Any]],
    epss_rows: Sequence[tuple[Any, Any, Any, Any, Any, Any]],
    nvd_rows: Sequence[tuple[Any, Any, Any, Any, Any, Any]],
    metric_rows: Sequence[tuple[Any, Any, Any, Any, Any, Any, Any, Any, Any, Any]],
) -> dict[str, Any]:
    """Join only NVD-returned CVEs to selected KEV/EPSS. Input tuples are read-only.

    Input contracts come from EA-03A4C and EA-03A4D1; all NVD CVEs are retained.
    Multiple CVSS metrics remain separate, with no inferred preferred metric.
    """
    try:
        policy = validate_time_coverage(
            selection, cutoff_date=cutoff_date,
            acknowledge_bounded_nvd=acknowledge_bounded_nvd,
            nvd_cves=[row[:4] for row in nvd_rows],
            kev_records=kev_rows,
        )
    except TimeCoverageError as exc:
        raise BoundedJoinError(f"Time/coverage preflight rejected join: {exc}") from exc

    kev = _unique(kev_rows, 1, "KEV")
    epss = _unique(epss_rows, 1, "EPSS")
    nvd = _unique(nvd_rows, 1, "NVD")
    _require(len(epss) == selection["epss"]["row_count"],
             "EPSS population count changed after source preflight")
    _require(len(kev) == selection["kev"]["row_count"],
             "KEV population count changed after source preflight")
    _require(len(nvd) == selection["nvd"]["cve_count"],
             "NVD population count changed after source preflight")

    for sid, cve, score_day, model, score, percentile in epss_rows:
        _require(sid == selection["epss"]["snapshot_id"],
                 "EPSS record belongs to another snapshot")
        _require(isinstance(score_day, date) and not hasattr(score_day, "hour")
                 and score_day.isoformat() == selection["epss"]["source_date"],
                 "EPSS score date changed")
        _require(model == selection["epss"]["model_version"],
                 "EPSS model version changed")
        _probability(score, f"EPSS {cve}")
        _probability(percentile, f"EPSS percentile {cve}")

    metrics: dict[str, list[dict[str, Any]]] = {cve: [] for cve in nvd}
    indices: dict[str, set[int]] = {cve: set() for cve in nvd}
    for row in metric_rows:
        (qid, cve, index, key, version, source, kind, vector,
         base_score, severity) = row
        _require(qid == selection["nvd"]["query_id"] and cve in nvd,
                 "NVD metric belongs to another query or CVE")
        _require(type(index) is int and index >= 0 and index not in indices[cve],
                 "NVD metric index invalid or duplicated")
        _require(version in CVSS_VERSIONS, "NVD CVSS version unsupported")
        _require(base_score is None or (type(base_score) in (int, float)
                 and math.isfinite(base_score) and 0 <= base_score <= 10),
                 "NVD CVSS base score invalid")
        indices[cve].add(index)
        metrics[cve].append({
            "metric_index": index, "metric_key": key, "cvss_version": version,
            "metric_source": source, "metric_type": kind, "vector_string": vector,
            "base_score": base_score, "base_severity": severity,
        })
    for cve in nvd:
        _require(indices[cve] == set(range(len(indices[cve]))),
                 "NVD metric index gap")
        metrics[cve].sort(key=lambda item: item["metric_index"])
    _require(sum(map(len, metrics.values())) == selection["nvd"]["cvss_metric_count"],
             "NVD CVSS metric count changed after selection")

    records: list[dict[str, Any]] = []
    for qid, cve, published, modified, status, page_hash in sorted(
        nvd_rows, key=lambda row: row[1]
    ):
        _require(qid == selection["nvd"]["query_id"],
                 "NVD query identity changed")
        _require(isinstance(page_hash, str) and len(page_hash) == 64
                 and all(ch in "0123456789abcdef" for ch in page_hash),
                 "NVD source page lineage invalid")
        kev_row = kev.get(cve)
        epss_row = epss.get(cve)
        records.append({
            "cve_id": cve,
            "nvd": {
                "query_id": qid, "vuln_status": status,
                "published_source_timestamp": published,
                "modified_source_timestamp": modified,
                "source_page_sha256": page_hash,
                "cvss_metrics": metrics[cve],
            },
            "kev": {
                "listed_in_selected_snapshot": kev_row is not None,
                "date_added": kev_row[2].isoformat() if kev_row else None,
            },
            "epss": {
                "has_score_in_selected_snapshot": epss_row is not None,
                "score": float(epss_row[4]) if epss_row else None,
                "percentile": float(epss_row[5]) if epss_row else None,
            },
        })

    return {
        "schema_id": JOIN_VERSION,
        "status": "local_bounded_nvd_cve_join_executed",
        "data_kind": "source_scoped_local_analysis",
        "row_scope": "only_cves_returned_by_one_bounded_nvd_query",
        "analysis_cutoff_date": policy["analysis_cutoff_date"],
        "time_precision": "calendar_date_guard_only_not_as_of_reconstruction",
        "selection_contract": selection["schema_id"],
        "time_coverage_contract": policy["schema_id"],
        "source_ids": {
            "nvd_query_id": selection["nvd"]["query_id"],
            "nvd_query_mode": selection["nvd"]["query_mode"],
            "kev_snapshot_id": selection["kev"]["snapshot_id"],
            "kev_source_date": selection["kev"]["source_date"],
            "epss_snapshot_id": selection["epss"]["snapshot_id"],
            "epss_score_date": selection["epss"]["source_date"],
            "epss_model_version": selection["epss"]["model_version"],
        },
        "coverage": {
            "nvd_query_cves": len(records),
            "in_selected_kev_snapshot": sum(r["kev"]["listed_in_selected_snapshot"] for r in records),
            "with_selected_epss_score": sum(r["epss"]["has_score_in_selected_snapshot"] for r in records),
            "nvd_cvss_metric_rows": sum(len(r["nvd"]["cvss_metrics"]) for r in records),
            "missing_nvd_cves_outside_query_are_unknown": True,
        },
        "cross_source_join_executed": True,
        "historical_as_of_reconstruction_attested": False,
        "nvd_global_coverage_attested": False,
        "organization_asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
        "published_to_public_demo": False,
        "interpretation": (
            "This local-only CVE overlap is anchored to a single bounded NVD query. "
            "KEV membership and EPSS scores refer only to their named selected snapshots; "
            "missing EPSS is null, not zero. All CVSS metrics remain source-specific. "
            "Calendar-date safeguards do not prove coherent point-in-time records, "
            "and no NVD absence, asset exposure, risk score or remediation is inferred."
        ),
        "records": records,
    }


def inspect_bounded_join(*, analytics_database: Path, nvd_database: Path,
                         cutoff_date: str, acknowledge_bounded_nvd: bool) -> dict[str, Any]:
    """Run both existing source gates before loading selected rows read-only."""
    import duckdb

    from patchline.warehouse.cross_source_contract import (
        SourceContractError,
        inspect_source_selection,
    )
    from patchline.warehouse.cross_source_policy import inspect_time_coverage

    try:
        selection = inspect_source_selection(
            analytics_database=analytics_database, nvd_database=nvd_database
        )
        inspect_time_coverage(
            analytics_database=analytics_database, nvd_database=nvd_database,
            cutoff_date=cutoff_date,
            acknowledge_bounded_nvd=acknowledge_bounded_nvd,
        )
        with duckdb.connect(str(analytics_database), read_only=True) as con:
            kev_rows = con.execute(
                "SELECT snapshot_id, cve_id, date_added FROM main.raw_kev_snapshot"
            ).fetchall()
            epss_rows = con.execute(
                """SELECT snapshot_id, cve_id, score_date, model_version, epss,
                          percentile FROM main.raw_epss_daily"""
            ).fetchall()
        with duckdb.connect(str(nvd_database), read_only=True) as con:
            nvd_rows = con.execute(
                """SELECT query_id, cve_id, published_source_timestamp,
                          modified_source_timestamp, vuln_status, source_page_sha256
                   FROM nvd_stage.cves"""
            ).fetchall()
            metric_rows = con.execute(
                """SELECT query_id, cve_id, metric_index, metric_key, cvss_version,
                          metric_source, metric_type, vector_string, base_score,
                          base_severity FROM nvd_stage.cvss_metrics"""
            ).fetchall()
    except (duckdb.Error, SourceContractError, TimeCoverageError, OSError) as exc:
        raise BoundedJoinError(f"Read-only selection failed: {exc}") from exc

    return build_bounded_join(
        selection, cutoff_date=cutoff_date,
        acknowledge_bounded_nvd=acknowledge_bounded_nvd,
        kev_rows=kev_rows, epss_rows=epss_rows,
        nvd_rows=nvd_rows, metric_rows=metric_rows,
    )


def save_local_no_replace(report: Mapping[str, Any], *, output: Path,
                          forbidden_inputs: Sequence[Path]) -> None:
    """Create a separate local JSON atomically; never overwrite or write under Git."""
    target = Path(output).absolute()
    _require(target.suffix.lower() == ".json", "Output must be a .json file")
    _require(target.parent.is_dir() and not target.parent.is_symlink(),
             "Output parent must be an existing real directory")
    _require(not target.exists() and not target.is_symlink(),
             "Output exists or is symlinked; refusing overwrite")
    _require(all(target != path.resolve() for path in forbidden_inputs),
             "Output must not equal an input database")
    parent = target.parent.resolve()
    _require(not any((p / ".git").exists() for p in (parent, *parent.parents)),
             "Output cannot be placed in a Git working tree")
    payload = (json.dumps(report, sort_keys=True, indent=2,
                          ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    fd, scratch = tempfile.mkstemp(prefix=".ea03a4d2-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Atomic no-replace on NTFS (same idiom as existing NVD staging code).
        os.link(scratch, target)
    finally:
        Path(scratch).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analytics-db", required=True, type=Path)
    parser.add_argument("--nvd-db", required=True, type=Path)
    parser.add_argument("--cutoff-date", required=True)
    parser.add_argument("--acknowledge-bounded-nvd", action="store_true")
    parser.add_argument("--execute-bounded-join", action="store_true",
                        help="Required explicit opt-in for joining source-scoped CVEs")
    parser.add_argument("--output", required=True, type=Path,
                        help="New local JSON outside the Git repository (never overwritten)")
    args = parser.parse_args(argv)
    try:
        _require(args.execute_bounded_join is True,
                 "Explicit --execute-bounded-join opt-in required")
        report = inspect_bounded_join(
            analytics_database=args.analytics_db,
            nvd_database=args.nvd_db,
            cutoff_date=args.cutoff_date,
            acknowledge_bounded_nvd=args.acknowledge_bounded_nvd,
        )
        save_local_no_replace(
            report, output=args.output,
            forbidden_inputs=(args.analytics_db, args.nvd_db),
        )
    except (BoundedJoinError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, sort_keys=True),
              file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "schema_id": JOIN_VERSION,
                      "output": str(args.output), "coverage": report["coverage"]},
                     sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
