"""EA-03A4C: offline, read-only compatibility gate for KEV, EPSS and a bounded NVD query.

This is NOT a CVE-level merge, a point-in-time reconciliation, or publication approval.
It validates source selection and reports only provenance and source-local row counts.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

import duckdb

CONTRACT_VERSION = "exploit-atlas.cross-source-selection.v1"
NVD_STAGE_VERSION = "patchline.nvd-duckdb-query-staging.v1"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
NVD_VERSIONS = {"2.0", "3.0", "3.1", "4.0"}
NVD_SCOPE_FLAGS = (
    "point_in_time_consistency_verified",
    "global_nvd_completeness_attested",
    "source_origin_independently_verified",
    "organization_asset_exposure_known",
)


class SourceContractError(ValueError):
    """Source selections cannot be safely described using this contract."""


def _require(ok: bool, why: str) -> None:
    if not ok:
        raise SourceContractError(why)


def _identifier(value: Any, *, label: str) -> str:
    _require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256")
    return value


def _date(value: Any, *, label: str) -> str:
    _require(isinstance(value, str) and len(value) >= 10,
             f"{label} missing or invalid")
    try:
        parsed = date.fromisoformat(value[:10])
    except ValueError as exc:
        raise SourceContractError(f"{label} missing or invalid") from exc
    _require(value[10:] in ("", "T00:00:00Z", "T00:00:00+00:00"),
             f"{label} not a supported source-date encoding")
    return parsed.isoformat()


def _path(value: Path, *, label: str) -> Path:
    path = Path(value)
    _require(path.suffix.lower() == ".duckdb", f"{label} must be a DuckDB file")
    _require(not path.is_symlink() and path.is_file(),
             f"{label} missing or symlinked")
    return path


def _query(con: duckdb.DuckDBPyConnection, sql: str) -> list[tuple[Any, ...]]:
    return con.execute(sql).fetchall()


def _validate_analytics(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    rows = _query(con, """SELECT source, snapshot_id, retrieved_at_utc, source_date,
                         model_version, row_count FROM main.source_snapshots""")
    _require(len(rows) == 2 and {r[0] for r in rows} == {"kev", "epss"},
             "KEV/EPSS selection requires exactly one snapshot for each source")
    snapshots: dict[str, dict[str, Any]] = {}
    for source, sid, retrieved, source_date, model, expected in rows:
        _identifier(sid, label=f"{source} snapshot_id")
        _require(isinstance(retrieved, str) and bool(retrieved.strip()),
                 f"{source} retrieved_at_utc missing")
        _require(type(expected) is int and expected >= 0,
                 f"{source} row_count invalid")
        snapshots[source] = {
            "snapshot_id": sid,
            "source_date": _date(source_date, label=f"{source} source_date"),
            "retrieved_at_utc": retrieved,
            "row_count": expected,
        }
        if source == "epss":
            _require(isinstance(model, str) and bool(model.strip()),
                     "EPSS model version missing")
            snapshots[source]["model_version"] = model

    kev_rows = _query(con, "SELECT snapshot_id, cve_id FROM main.raw_kev_snapshot")
    epss_rows = _query(con, """SELECT snapshot_id, cve_id, score_date, epss, percentile
                              FROM main.raw_epss_daily""")
    for source, table_rows in (("kev", kev_rows), ("epss", epss_rows)):
        _require(len(table_rows) == snapshots[source]["row_count"],
                 f"{source} raw count disagrees with selected snapshot registry")
        seen: set[str] = set()
        for row in table_rows:
            sid, cve_id = row[0], row[1]
            _require(sid == snapshots[source]["snapshot_id"],
                     f"{source} raw row belongs to another snapshot")
            _require(isinstance(cve_id, str) and CVE_RE.fullmatch(cve_id) is not None,
                     f"{source} raw CVE identifier invalid")
            _require(cve_id not in seen, f"{source} raw CVE identifier duplicated")
            seen.add(cve_id)
            if source == "epss":
                _, _, score_date, score, percentile = row
                _require(str(score_date) == snapshots[source]["source_date"],
                         "EPSS score date differs from selected snapshot date")
                for key, value in (("score", score), ("percentile", percentile)):
                    _require(type(value) in (int, float) and math.isfinite(value)
                             and 0 <= value <= 1, f"EPSS {key} outside [0, 1]")
    return snapshots


def _validate_nvd(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    registry = _query(con, """SELECT contract_version, query_id, query_manifest_sha256,
                           normalized_sha256, source, query_mode, record_count,
                           metric_count, page_count,
                           point_in_time_consistency_verified,
                           global_nvd_completeness_attested,
                           source_origin_independently_verified,
                           organization_asset_exposure_known
                           FROM nvd_stage.query_registry""")
    _require(len(registry) == 1, "Expected exactly one bounded NVD query registry row")
    (version, query_id, manifest_hash, normalized_hash, source, query_mode,
     cve_count, metric_count, page_count, *scope) = registry[0]
    _require(version == NVD_STAGE_VERSION, "Unexpected NVD DuckDB staging contract")
    for value, label in ((query_id, "NVD query_id"),
                         (manifest_hash, "NVD query_manifest_sha256"),
                         (normalized_hash, "NVD normalized_sha256")):
        _identifier(value, label=label)
    _require(source == "NVD_CVE", "Unexpected NVD data source")
    _require(isinstance(query_mode, str) and bool(query_mode.strip()),
             "NVD query mode missing")
    for label, value in (("record_count", cve_count), ("metric_count", metric_count),
                         ("page_count", page_count)):
        _require(type(value) is int and value >= 0, f"NVD {label} invalid")
    _require(all(value is False for value in scope),
             "NVD query falsely asserts completeness, origin, consistency or exposure")

    cves = _query(con, """SELECT query_id, cve_id, record_index, source_page_sha256
                         FROM nvd_stage.cves""")
    _require(len(cves) == cve_count, "NVD CVE records disagree with query registry")
    ids: set[str] = set()
    positions: set[int] = set()
    for row_query, cve, position, page_sha in cves:
        _require(row_query == query_id, "NVD CVE belongs to another query")
        _require(isinstance(cve, str) and CVE_RE.fullmatch(cve) is not None,
                 "NVD CVE identifier invalid")
        _require(cve not in ids, "NVD duplicate CVE identifier")
        _require(type(position) is int and position >= 0 and position not in positions,
                 "NVD CVE order invalid or duplicate")
        _identifier(page_sha, label="NVD CVE page SHA-256")
        ids.add(cve)
        positions.add(position)
    _require(positions == set(range(cve_count)), "NVD CVE positions not contiguous")

    metrics = _query(con, """SELECT query_id, cve_id, metric_index, cvss_version,
                           base_score FROM nvd_stage.cvss_metrics""")
    _require(len(metrics) == metric_count, "NVD CVSS count disagrees with query registry")
    keys: set[tuple[str, int]] = set()
    for row_query, cve, index, version, score in metrics:
        _require(row_query == query_id and cve in ids,
                 "NVD metric belongs to another query or an unknown CVE")
        _require(type(index) is int and index >= 0 and (cve, index) not in keys,
                 "NVD metric index duplicated or invalid")
        _require(version in NVD_VERSIONS, "Unsupported NVD CVSS version")
        _require(score is None or (type(score) in (int, float)
                 and math.isfinite(score) and 0 <= score <= 10),
                 "NVD CVSS score out of range")
        keys.add((cve, index))
    for cve in ids:
        ordered = sorted(idx for key_cve, idx in keys if key_cve == cve)
        _require(ordered == list(range(len(ordered))),
                 "NVD CVSS metric positions not contiguous")

    return {
        "query_id": query_id,
        "query_mode": query_mode,
        "source": source,
        "query_manifest_sha256": manifest_hash,
        "normalized_sha256": normalized_hash,
        "cve_count": cve_count,
        "cvss_metric_count": metric_count,
        "page_count": page_count,
        "source_scope_flags": dict(zip(NVD_SCOPE_FLAGS, scope, strict=True)),
    }


def inspect_source_selection(*, analytics_database: Path, nvd_database: Path) -> dict[str, Any]:
    """Inspect two existing databases without writing to either or joining their CVEs."""
    analytics = _path(analytics_database, label="KEV/EPSS database")
    nvd = _path(nvd_database, label="NVD database")
    _require(not analytics.samefile(nvd), "Two separate databases required")
    try:
        with duckdb.connect(str(analytics), read_only=True) as con:
            snapshots = _validate_analytics(con)
        with duckdb.connect(str(nvd), read_only=True) as con:
            nvd_selection = _validate_nvd(con)
    except duckdb.Error as exc:
        raise SourceContractError(f"Read-only source validation failed: {exc}") from exc
    return {
        "schema_id": CONTRACT_VERSION,
        "status": "source_selection_validated_no_join",
        "kev": snapshots["kev"],
        "epss": snapshots["epss"],
        "nvd": nvd_selection,
        "cross_source_join_executed": False,
        "join_approved": False,
        "point_in_time_alignment_attested": False,
        "nvd_global_coverage_attested": False,
        "asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
        "interpretation": (
            "Local schemas, identities, counts, selected dates and scope flags pass "
            "the offline preflight. This is not a shared as-of date, a global NVD "
            "snapshot, a cryptographic recheck of raw archives or authorization "
            "to publish joined CVE results."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analytics-db", type=Path, required=True)
    parser.add_argument("--nvd-db", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        answer = inspect_source_selection(
            analytics_database=args.analytics_db, nvd_database=args.nvd_db
        )
    except (SourceContractError, OSError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(answer, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
