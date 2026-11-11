"""Deterministic, explicitly synthetic DuckDB warehouse for offline dbt CI."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import duckdb

KEV_ID = hashlib.sha256(b"patchline-ci-synthetic-kev-v1").hexdigest()
EPSS_ID = hashlib.sha256(b"patchline-ci-synthetic-epss-v1").hexdigest()
KEV_COUNT = 3
EPSS_COUNT = 4


def create_fixture(output: Path) -> None:
    """Create a small P3.1-shaped fixture without overwriting any database."""
    if output.exists():
        raise ValueError(f"Refusing to overwrite existing database: {output}")
    if not output.parent.is_dir():
        raise ValueError(f"Output directory does not exist: {output.parent}")

    # All data are invented for offline checks; never report these as live CVE data.
    connection = duckdb.connect(str(output))
    try:
        connection.execute("BEGIN TRANSACTION")
        connection.execute("""CREATE TABLE main.source_snapshots (
            source VARCHAR NOT NULL PRIMARY KEY,
            snapshot_id VARCHAR NOT NULL,
            retrieved_at_utc VARCHAR NOT NULL,
            source_date VARCHAR NOT NULL,
            model_version VARCHAR,
            row_count BIGINT NOT NULL
        )""")
        connection.execute("""CREATE TABLE main.raw_kev_snapshot (
            snapshot_id VARCHAR NOT NULL,
            cve_id VARCHAR NOT NULL,
            date_added DATE NOT NULL,
            due_date DATE NOT NULL,
            vendor_project VARCHAR,
            product VARCHAR,
            vulnerability_name VARCHAR,
            known_ransomware_campaign_use VARCHAR,
            PRIMARY KEY (snapshot_id, cve_id)
        )""")
        connection.execute("""CREATE TABLE main.raw_epss_daily (
            snapshot_id VARCHAR NOT NULL,
            score_date DATE NOT NULL,
            model_version VARCHAR NOT NULL,
            cve_id VARCHAR NOT NULL,
            epss DOUBLE NOT NULL,
            percentile DOUBLE NOT NULL,
            PRIMARY KEY (snapshot_id, cve_id)
        )""")
        connection.executemany(
            "INSERT INTO main.source_snapshots VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("kev", KEV_ID, "2026-01-15T12:00:00Z", "2026-01-15T00:00:00Z", None, KEV_COUNT),
                ("epss", EPSS_ID, "2026-01-15T12:30:00Z", "2026-01-15", "v-ci-synthetic", EPSS_COUNT),
            ],
        )
        connection.executemany(
            "INSERT INTO main.raw_kev_snapshot VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (KEV_ID, "CVE-2099-0001", "2026-01-10", "2026-02-10", "Example Co", "Widget", "Example A", "Unknown"),
                (KEV_ID, "CVE-2099-0002", "2026-01-11", "2026-02-11", "Example Co", "", "Example B", "Known"),
                (KEV_ID, "CVE-2099-0003", "2026-01-12", "2026-02-12", "Demo Inc", "Engine", "Example C", "Unknown"),
            ],
        )
        connection.executemany(
            "INSERT INTO main.raw_epss_daily VALUES (?, ?, ?, ?, ?, ?)",
            [
                (EPSS_ID, "2026-01-15", "v-ci-synthetic", "CVE-2099-0001", 0.01, 0.2),
                (EPSS_ID, "2026-01-15", "v-ci-synthetic", "CVE-2099-0002", 0.8, 0.95),
                (EPSS_ID, "2026-01-15", "v-ci-synthetic", "CVE-2099-9001", 0.0, 0.0),
                (EPSS_ID, "2026-01-15", "v-ci-synthetic", "CVE-2099-9002", 1.0, 1.0),
            ],
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        connection.close()
        output.unlink(missing_ok=True)
        raise
    else:
        connection.close()


def verify_staging(database: Path) -> None:
    """Verify dbt views exist, raw row counts match, and fixture stays synthetic."""
    if not database.is_file():
        raise ValueError(f"Fixture database missing: {database}")
    with duckdb.connect(str(database), read_only=True) as connection:
        models = connection.execute("""SELECT table_name, table_type
            FROM information_schema.tables
            WHERE table_schema = 'analytics_staging'
            ORDER BY table_name""").fetchall()
        if models != [("stg_epss", "VIEW"), ("stg_kev", "VIEW")]:
            raise ValueError(f"Unexpected staging objects: {models}")
        for raw, staged, expected in (
            ("raw_kev_snapshot", "stg_kev", KEV_COUNT),
            ("raw_epss_daily", "stg_epss", EPSS_COUNT),
        ):
            raw_count = connection.execute(f"SELECT count(*) FROM main.{raw}").fetchone()[0]
            stage_count = connection.execute(
                f"SELECT count(*) FROM analytics_staging.{staged}"
            ).fetchone()[0]
            if raw_count != expected or stage_count != expected:
                raise ValueError(f"Row-count mismatch in {staged}: {raw_count} / {stage_count}")
        ids = connection.execute(
            "SELECT source, snapshot_id FROM main.source_snapshots ORDER BY source"
        ).fetchall()
        if ids != [("epss", EPSS_ID), ("kev", KEV_ID)]:
            raise ValueError("Unexpected synthetic snapshot lineage")
        actual_overlap = connection.execute("""SELECT count(*)
            FROM analytics_staging.stg_kev k
            JOIN analytics_staging.stg_epss e USING (cve_id)""").fetchone()[0]
        if actual_overlap != 2:
            raise ValueError("Expected exactly two matching fixture CVEs")



def verify_joins(database: Path) -> None:
    """Assert exact synthetic full-outer-join results after a real dbt run."""
    verify_staging(database)
    with duckdb.connect(str(database), read_only=True) as connection:
        objects = connection.execute("""SELECT table_name, table_type
            FROM information_schema.tables
            WHERE table_schema = 'analytics_intermediate'""").fetchall()
        if objects != [("int_kev_epss_overlap", "VIEW")]:
            raise ValueError(f"Unexpected intermediate objects: {objects}")
        rows = connection.execute("""SELECT cve_id, join_status, is_kev,
                has_epss_score, epss, percentile, kev_snapshot_id, epss_snapshot_id,
                score_date, date_added
            FROM analytics_intermediate.int_kev_epss_overlap
            ORDER BY cve_id""").fetchall()
        expected = [
            ("CVE-2099-0001", "both", True, True, 0.01, 0.2),
            ("CVE-2099-0002", "both", True, True, 0.8, 0.95),
            ("CVE-2099-0003", "kev_only", True, False, None, None),
            ("CVE-2099-9001", "epss_only", False, True, 0.0, 0.0),
            ("CVE-2099-9002", "epss_only", False, True, 1.0, 1.0),
        ]
        for actual, (cve, status, in_kev, scored, score, percentile) in zip(
            rows, expected, strict=True
        ):
            if actual[:6] != (cve, status, in_kev, scored, score, percentile):
                raise ValueError(f"Unexpected join result for {cve}: {actual[:6]}")
            if actual[6:8] != (KEV_ID, EPSS_ID):
                raise ValueError(f"Invalid paired lineage for {cve}")
            if (actual[8] is not None) != scored or (actual[9] is not None) != in_kev:
                raise ValueError(f"Invalid source-specific null policy for {cve}")
        if len(rows) != len(expected):
            raise ValueError(f"Unexpected joined CVE count: {len(rows)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify", "verify-joins"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "create":
        create_fixture(args.output)
        print(f"Synthetic CI warehouse created: {args.output}")
    elif args.action == "verify":
        verify_staging(args.output)
        print("Synthetic CI staging verification passed (3 KEV, 4 EPSS, 2 matched)")
    else:
        verify_joins(args.output)
        print("Synthetic CI join verification passed (2 both, 1 KEV-only, 2 EPSS-only)")


if __name__ == "__main__":
    main()
