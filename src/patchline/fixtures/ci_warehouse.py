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




def verify_m03(database: Path) -> None:
    """Verify the real dbt M03 view against synthetic source-pair expectations."""
    verify_joins(database)
    with duckdb.connect(str(database), read_only=True) as connection:
        objects = connection.execute("""SELECT table_name, table_type
            FROM information_schema.tables
            WHERE table_schema = 'analytics_marts'""").fetchall()
        if ("m03_epss_coverage_of_kev", "VIEW") not in objects:
            raise ValueError(f"Unexpected M03 objects: {objects}")
        rows = connection.execute("""SELECT metric_id, metric_label, metric_unit,
                kev_snapshot_id, epss_snapshot_id, kev_catalog_date_released,
                epss_source_date, epss_model_version, numerator_matched_kev,
                denominator_total_kev, unmatched_kev, coverage_percent,
                population, filter_definition, null_policy, caveat,
                kev_retrieved_at_utc, epss_retrieved_at_utc
            FROM analytics_marts.m03_epss_coverage_of_kev""").fetchall()
        if len(rows) != 1:
            raise ValueError(f"Expected one M03 row, got {len(rows)}")
        row = rows[0]
        expected = (
            "M03", "EPSS coverage of KEV", "percent", KEV_ID, EPSS_ID,
            "2026-01-15T00:00:00Z", "2026-01-15", "v-ci-synthetic",
            2, 3, 1,
        )
        if row[:11] != expected:
            raise ValueError(f"Unexpected M03 counts or source lineage: {row[:11]}")
        if abs(row[11] - 200.0 / 3.0) > 1e-9:
            raise ValueError(f"Unexpected M03 percentage: {row[11]}")
        if any(not isinstance(value, str) or not value.strip() for value in row[12:]):
            raise ValueError("M03 population, caveats or retrieval metadata missing")


def verify_m04(database: Path) -> None:
    """Verify complete EPSS score-band and interpolated-quantile metrics."""
    verify_m03(database)
    with duckdb.connect(str(database), read_only=True) as connection:
        names = {r[0] for r in connection.execute("""SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'analytics_marts'""").fetchall()}
        required = {
            "m03_epss_coverage_of_kev",
            "m04_epss_population_summary",
            "m04_epss_score_bands",
        }
        if names not in (required, required | {"m05_kev_epss_cohort_bands"}):
            raise ValueError(f"Unexpected M04 mart objects: {names}")

        summary = connection.execute("""SELECT metric_id, epss_snapshot_id,
            epss_source_date, epss_model_version, scored_cve_count, null_score_count,
            min_epss, max_epss, mean_epss, p25_epss, median_epss, p75_epss, p90_epss,
            population, caveat, epss_retrieved_at_utc
            FROM analytics_marts.m04_epss_population_summary""").fetchall()
        if len(summary) != 1:
            raise ValueError(f"Expected one M04 summary row, got {len(summary)}")
        row = summary[0]
        if row[:6] != ("M04", EPSS_ID, "2026-01-15", "v-ci-synthetic", 4, 0):
            raise ValueError(f"Unexpected M04 lineage or population: {row[:6]}")
        expected_scores = (0.0, 1.0, 0.4525, 0.0075, 0.405, 0.85, 0.94)
        if any(
            abs(actual - expected) > 1e-10
            for actual, expected in zip(row[6:13], expected_scores, strict=True)
        ):
            raise ValueError(f"Unexpected M04 score statistics: {row[6:13]}")
        if not all(isinstance(v, str) and v.strip() for v in row[13:]):
            raise ValueError("M04 population, caveat or retrieval metadata missing")

        bands = connection.execute("""SELECT band_order, cve_count,
            denominator_scored_cves, population_percent, epss_snapshot_id,
            epss_source_date, upper_inclusive
            FROM analytics_marts.m04_epss_score_bands ORDER BY band_order""").fetchall()
        if len(bands) != 5:
            raise ValueError(f"Expected exactly five M04 bands, got {len(bands)}")
        for band, expected_count in zip(bands, (1, 0, 1, 0, 2), strict=True):
            order, count, denominator, percent, snap, source_date, inclusive = band
            if count != expected_count or denominator != 4 or order not in range(1, 6):
                raise ValueError(f"Unexpected M04 score band: {band}")
            if abs(percent - 25.0 * expected_count) > 1e-10:
                raise ValueError(f"Unexpected M04 band share: {band}")
            if snap != EPSS_ID or source_date != "2026-01-15" or inclusive != (order == 5):
                raise ValueError(f"Unexpected M04 band lineage or boundary: {band}")


def verify_m05(database: Path) -> None:
    """Verify M05 counts, three distinct denominators, and paired provenance."""
    verify_m04(database)
    with duckdb.connect(str(database), read_only=True) as connection:
        rows = connection.execute("""SELECT band_order, metric_id, cohort_category,
            band_label, kev_cve_count, denominator_all_kev, denominator_scored_kev,
            unscored_kev, share_all_kev_percent, share_scored_kev_percent,
            full_epss_band_count, full_epss_denominator, full_epss_population_percent,
            lower_bound, upper_bound, upper_inclusive, kev_snapshot_id, epss_snapshot_id,
            kev_catalog_date_released, epss_source_date, epss_model_version
            FROM analytics_marts.m05_kev_epss_cohort_bands ORDER BY band_order""").fetchall()
        if len(rows) != 6:
            raise ValueError(f"Expected exactly six M05 cohorts, got {len(rows)}")
        kev_expected = (0, 0, 1, 0, 1, 1)
        epss_expected = (1, 0, 1, 0, 2)
        for order, row in enumerate(rows, start=1):
            (number, metric, category, label, count, all_kev, scored_kev, unmatched,
             all_share, scored_share, full_count, full_total, full_share,
             lower, upper, inclusive, kev_id, epss_id, kev_date, epss_date,
             model_version) = row
            if (number, metric, count, all_kev, scored_kev, unmatched) != (
                order, "M05", kev_expected[order - 1], 3, 2, 1
            ):
                raise ValueError(f"Incorrect M05 cohort count or denominators: {row}")
            if (kev_id, epss_id, kev_date, epss_date, model_version) != (
                KEV_ID, EPSS_ID, "2026-01-15T00:00:00Z", "2026-01-15", "v-ci-synthetic"
            ):
                raise ValueError(f"M05 source lineage mismatch: {row}")
            if abs(all_share - 100 * count / 3) > 1e-9:
                raise ValueError(f"Incorrect M05 all-KEV share: {row}")
            if order < 6:
                if category != "scored_band" or (full_count, full_total) != (
                    epss_expected[order - 1], 4
                ):
                    raise ValueError(f"Incorrect M05 full EPSS comparison: {row}")
                if (abs(scored_share - 100 * count / 2) > 1e-9
                        or abs(full_share - 25 * full_count) > 1e-9):
                    raise ValueError(f"Incorrect M05 population shares: {row}")
                if label is None or lower is None or upper is None or inclusive != (order == 5):
                    raise ValueError(f"Invalid M05 score-band definitions: {row}")
            elif (category != "unscored_kev" or label != "No matching EPSS score"
                  or any(v is not None for v in
                         (scored_share, full_count, full_total, full_share, lower,
                          upper, inclusive))):
                raise ValueError(f"Unscored KEV must not be given a score: {row}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify", "verify-joins", "verify-m03", "verify-m04", "verify-m05"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "create":
        create_fixture(args.output)
        print(f"Synthetic CI warehouse created: {args.output}")
    elif args.action == "verify":
        verify_staging(args.output)
        print("Synthetic CI staging verification passed (3 KEV, 4 EPSS, 2 matched)")
    elif args.action == "verify-joins":
        verify_joins(args.output)
        print("Synthetic CI join verification passed (2 both, 1 KEV-only, 2 EPSS-only)")
    elif args.action == "verify-m03":
        verify_m03(args.output)
        print("Synthetic CI M03 verification passed "
              "(2 matched / 3 KEV, 1 unmatched, 66.666... percent)")
    elif args.action == "verify-m04":
        verify_m04(args.output)
        print("Synthetic CI M04 verification passed "
              "(4 EPSS CVEs, 5 bands, 0 and 1 preserved, quantiles reconciled)")
    else:
        verify_m05(args.output)
        print("Synthetic CI M05 verification passed "
              "(KEV counts 0, 0, 1, 0, 1, 1; denominators 3 KEV, 2 matched, 4 EPSS)")


if __name__ == "__main__":
    main()
