"""EA-03A4A: verified, offline NVD query -> isolated DuckDB staging.

A separate, content-pinned database is written for ONE verified query. This
module neither updates the existing KEV/EPSS warehouse nor publishes UI data.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import duckdb

from patchline.ingest.nvd_query_normalize import (
    NVDQueryNormalizationError,
    _json_bytes,
    inspect_archived_nvd_query,
)

STAGING_CONTRACT = "patchline.nvd-duckdb-query-staging.v1"
NORMALIZED_CONTRACT = "patchline.nvd-normalized-query.v1"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

REGISTRY_COLUMNS = (
    "contract_version", "query_id", "query_manifest_sha256", "normalized_sha256",
    "source", "query_mode", "record_count", "metric_count", "page_count",
    "point_in_time_consistency_verified", "global_nvd_completeness_attested",
    "source_origin_independently_verified", "organization_asset_exposure_known",
)
CVE_COLUMNS = (
    "query_id", "record_index", "cve_id", "source_identifier", "vuln_status",
    "published_source_timestamp", "modified_source_timestamp", "description_en",
    "source_page_sha256", "source_page_start_index", "source_page_record_index",
    "missing_english_description", "missing_cvss_metrics", "missing_weaknesses",
    "missing_configurations", "missing_references", "record_json",
)
METRIC_COLUMNS = (
    "query_id", "cve_id", "metric_index", "metric_key", "cvss_version",
    "metric_source", "metric_type", "vector_string", "base_score", "base_severity",
    "source_metric_json",
)


class NVDWarehouseError(ValueError):
    """Refuse incomplete, unverified, conflicting, or mutable warehouse input."""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _fail(reason: str) -> None:
    raise NVDWarehouseError(reason)


def _verified_projection(data_dir: Path, query_id: str) -> tuple[dict[str, Any], str]:
    if not isinstance(query_id, str) or SHA_RE.fullmatch(query_id) is None:
        _fail("query_id must be a lowercase SHA-256")
    try:
        projection = inspect_archived_nvd_query(data_dir, query_id=query_id)
    except (NVDQueryNormalizationError, OSError) as exc:
        raise NVDWarehouseError(f"NVD source verification failed: {exc}") from exc
    if projection.get("format_version") != NORMALIZED_CONTRACT:
        _fail("Unexpected normalized input contract")
    for key in (
        "point_in_time_consistency_verified", "global_nvd_completeness_attested",
        "source_origin_independently_verified", "organization_asset_exposure_known",
    ):
        if projection.get(key) is not False:
            _fail(f"Source scope flag differs from expected boundary: {key}")
    path = data_dir / "normalized" / "nvd-queries" / query_id / "normalized.json"
    if not path.is_file() or path.is_symlink():
        _fail("Required immutable normalized query file is missing")
    saved = path.read_bytes()
    if saved != _json_bytes(projection):
        _fail("Normalized query bytes differ from verified source projection")
    return projection, hashlib.sha256(saved).hexdigest()


def _expected_rows(
    projection: dict[str, Any], normalized_sha: str
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    query_id = projection["query_id"]
    records = projection["records"]
    cve_rows: list[tuple[Any, ...]] = []
    metric_rows: list[tuple[Any, ...]] = []
    for number, record in enumerate(records):
        missing = record["missing"]
        cve_rows.append((
            query_id, number, record["cve_id"], record["source_identifier"],
            record["vuln_status"], record["published_source_timestamp"],
            record["modified_source_timestamp"], record["description_en"],
            record["source_page_sha256"], record["source_page_start_index"],
            record["source_page_record_index"], missing["english_description"],
            missing["cvss_metrics"], missing["weaknesses"],
            missing["configurations"], missing["references"], _json(record),
        ))
        for metric_index, metric in enumerate(record["cvss_metrics"]):
            metric_rows.append((
                query_id, record["cve_id"], metric_index, metric["metric_key"],
                metric["cvss_version"], metric["source"], metric["type"],
                metric["vector_string"], metric["base_score"], metric["base_severity"],
                _json(metric["source_metric"]),
            ))
    if len(cve_rows) != projection["record_count"] or len(records) != projection["reported_total_results"]:
        _fail("Projection count does not match NVD reported query total")
    registry = [(
        STAGING_CONTRACT, query_id, projection["query_manifest_sha256"],
        normalized_sha, projection["source"], projection["query_mode"],
        len(cve_rows), len(metric_rows), len(projection["source_pages"]),
        False, False, False, False,
    )]
    return registry, cve_rows, metric_rows


def _ddl(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("CREATE SCHEMA nvd_stage")
    con.execute("""CREATE TABLE nvd_stage.query_registry (
        contract_version VARCHAR NOT NULL, query_id VARCHAR PRIMARY KEY,
        query_manifest_sha256 VARCHAR NOT NULL, normalized_sha256 VARCHAR NOT NULL,
        source VARCHAR NOT NULL, query_mode VARCHAR NOT NULL,
        record_count BIGINT NOT NULL, metric_count BIGINT NOT NULL, page_count BIGINT NOT NULL,
        point_in_time_consistency_verified BOOLEAN NOT NULL,
        global_nvd_completeness_attested BOOLEAN NOT NULL,
        source_origin_independently_verified BOOLEAN NOT NULL,
        organization_asset_exposure_known BOOLEAN NOT NULL
    )""")
    con.execute("""CREATE TABLE nvd_stage.cves (
        query_id VARCHAR NOT NULL, record_index BIGINT NOT NULL,
        cve_id VARCHAR NOT NULL, source_identifier VARCHAR, vuln_status VARCHAR NOT NULL,
        published_source_timestamp VARCHAR NOT NULL,
        modified_source_timestamp VARCHAR NOT NULL, description_en VARCHAR,
        source_page_sha256 VARCHAR NOT NULL, source_page_start_index BIGINT NOT NULL,
        source_page_record_index BIGINT NOT NULL, missing_english_description BOOLEAN NOT NULL,
        missing_cvss_metrics BOOLEAN NOT NULL, missing_weaknesses BOOLEAN NOT NULL,
        missing_configurations BOOLEAN NOT NULL, missing_references BOOLEAN NOT NULL,
        record_json VARCHAR NOT NULL,
        PRIMARY KEY(query_id, cve_id), UNIQUE(query_id, record_index)
    )""")
    con.execute("""CREATE TABLE nvd_stage.cvss_metrics (
        query_id VARCHAR NOT NULL, cve_id VARCHAR NOT NULL,
        metric_index BIGINT NOT NULL, metric_key VARCHAR NOT NULL,
        cvss_version VARCHAR NOT NULL, metric_source VARCHAR, metric_type VARCHAR,
        vector_string VARCHAR, base_score DOUBLE, base_severity VARCHAR,
        source_metric_json VARCHAR NOT NULL,
        PRIMARY KEY(query_id, cve_id, metric_index)
    )""")


def _insert(con: duckdb.DuckDBPyConnection, table: str, rows: list[tuple[Any, ...]]) -> None:
    columns = {"query_registry": REGISTRY_COLUMNS, "cves": CVE_COLUMNS, "cvss_metrics": METRIC_COLUMNS}[table]
    if rows:
        params = ", ".join("?" for _ in columns)
        con.executemany(f"INSERT INTO nvd_stage.{table} VALUES ({params})", rows)


def _verify_database(path: Path, expected: tuple[list[tuple[Any, ...]], ...]) -> None:
    if not path.is_file() or path.is_symlink():
        _fail("Staging database missing or is a symlink")
    try:
        con = duckdb.connect(str(path), read_only=True)
        try:
            tables = {row[0] for row in con.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'nvd_stage' AND table_type = 'BASE TABLE'
            """).fetchall()}
            if tables != {"query_registry", "cves", "cvss_metrics"}:
                _fail("Staging table inventory mismatch")
            for table, columns, expected_rows, order in (
                ("query_registry", REGISTRY_COLUMNS, expected[0], "query_id"),
                ("cves", CVE_COLUMNS, expected[1], "record_index"),
                ("cvss_metrics", METRIC_COLUMNS, expected[2], "cve_id, metric_index"),
            ):
                column_names = tuple(row[0] for row in con.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema = 'nvd_stage' AND table_name = ?
                    ORDER BY ordinal_position
                """, [table]).fetchall())
                if column_names != columns:
                    _fail(f"Staging column contract mismatch: {table}")
                actual_rows = con.execute(
                    f"SELECT * FROM nvd_stage.{table} ORDER BY {order}"
                ).fetchall()
                reference = expected_rows
                if table == "cvss_metrics":
                    reference = sorted(expected_rows, key=lambda row: (row[1], row[2]))
                if actual_rows != reference:
                    _fail(f"Staging row or lineage mismatch: {table}")
        finally:
            con.close()
    except duckdb.Error as exc:
        raise NVDWarehouseError(f"Staging database cannot be verified: {exc}") from exc


def stage_nvd_query(
    data_dir: Path, *, query_id: str, database: Path | None = None
) -> dict[str, Any]:
    """Verify all original archives, then create/verify a standalone staging DB.

    Never opens an existing database for write. No other product warehouse is changed.
    """
    data_dir = Path(data_dir)
    projection, normalized_sha = _verified_projection(data_dir, query_id)
    rows = _expected_rows(projection, normalized_sha)
    target = Path(database) if database is not None else (
        data_dir / "warehouse" / "nvd-queries" / f"{query_id}.duckdb"
    )
    if target.exists() or target.is_symlink():
        _verify_database(target, rows)
        return {
            "status": "verified_existing", "contract_version": STAGING_CONTRACT,
            "query_id": query_id, "database_path": str(target),
            "cve_count": len(rows[1]), "cvss_metric_count": len(rows[2]),
            "normalized_sha256": normalized_sha,
            "point_in_time_consistency_verified": False,
        }
    if not target.parent.is_dir():
        target.parent.mkdir(parents=True, exist_ok=True)
    handle, scratch = tempfile.mkstemp(prefix=".ea03a4a-", suffix=".duckdb", dir=target.parent)
    os.close(handle)
    os.unlink(scratch)
    try:
        con = duckdb.connect(scratch)
        try:
            con.execute("BEGIN TRANSACTION")
            try:
                _ddl(con)
                for table, values in zip(
                    ("query_registry", "cves", "cvss_metrics"), rows, strict=True
                ):
                    _insert(con, table, values)
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
            con.execute("CHECKPOINT")
        finally:
            con.close()
        _verify_database(Path(scratch), rows)
        try:
            # Atomic no-replace publication on the same filesystem (Windows NTFS too).
            os.link(scratch, target)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            _verify_database(target, rows)
            status = "verified_existing"
        else:
            status = "staged"
    except (duckdb.Error, OSError) as exc:
        raise NVDWarehouseError(f"Staging failed without overwriting a database: {exc}") from exc
    finally:
        for path in (scratch, scratch + ".wal"):
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
    return {
        "status": status, "contract_version": STAGING_CONTRACT,
        "query_id": query_id, "database_path": str(target),
        "cve_count": len(rows[1]), "cvss_metric_count": len(rows[2]),
        "normalized_sha256": normalized_sha,
        "point_in_time_consistency_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, source-pinned NVD DuckDB staging")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--query-id", required=True)
    parser.add_argument("--database", type=Path)
    args = parser.parse_args(argv)
    try:
        result = stage_nvd_query(args.data_dir, query_id=args.query_id, database=args.database)
    except (NVDWarehouseError, OSError) as exc:
        print(f"NVD warehouse staging failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
