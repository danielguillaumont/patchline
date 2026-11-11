"""Export tested analytical marts to immutable, verified local bundles."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import shutil
import sys
import uuid
from decimal import Decimal
from pathlib import Path

import duckdb


class ExportError(ValueError):
    """The export contract or output safety invariant was not satisfied."""


MODELS = (
    ("m03_epss_coverage_of_kev", "analytics_marts.m03_epss_coverage_of_kev", "metric_id"),
    ("m04_epss_population_summary", "analytics_marts.m04_epss_population_summary", "metric_id"),
    ("m04_epss_score_bands", "analytics_marts.m04_epss_score_bands", "band_order"),
)
SCHEMA_ID = "patchline.analytics-export.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_value(value: object) -> object:
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ExportError("Non-finite analytical value cannot be exported")
        if value == value.to_integral_value():
            return int(value)
        number = float(value)
        if not math.isfinite(number):
            raise ExportError("Non-finite analytical value cannot be exported")
        return number
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        raise ExportError("Non-finite analytical value cannot be exported")
    return value


def _query(con: duckdb.DuckDBPyConnection, query: str) -> tuple[list[str], list[dict[str, object]]]:
    cursor = con.execute(query)
    columns = [desc[0] for desc in cursor.description]
    if len(columns) != len(set(columns)):
        raise ExportError("Duplicate analytical columns")
    rows = [dict(zip(columns, (_json_value(v) for v in row), strict=True))
            for row in cursor.fetchall()]
    return columns, rows


def _validate(con: duckdb.DuckDBPyConnection) -> dict[str, object]:
    """Check source-pair lineage and cross-mart accounting before writing outputs."""
    try:
        source_columns, sources = _query(con, """SELECT source, snapshot_id, source_date,
            retrieved_at_utc, model_version, row_count
            FROM main.source_snapshots ORDER BY source""")
        _ = source_columns
        if [s["source"] for s in sources] != ["epss", "kev"]:
            raise ExportError("Expected exactly one KEV and one EPSS source snapshot")
        by_source = {str(s["source"]): s for s in sources}
        _, m03 = _query(con, "SELECT * FROM analytics_marts.m03_epss_coverage_of_kev")
        _, summary = _query(con, "SELECT * FROM analytics_marts.m04_epss_population_summary")
        _, bands = _query(con, """SELECT * FROM analytics_marts.m04_epss_score_bands
            ORDER BY band_order""")
        if len(m03) != 1 or len(summary) != 1 or len(bands) != 5:
            raise ExportError("M03/M04 unexpected mart row counts")
        coverage = m03[0]
        population = summary[0]
        kev = by_source["kev"]
        epss = by_source["epss"]
        if coverage["metric_id"] != "M03" or population["metric_id"] != "M04":
            raise ExportError("Unexpected analytical metric IDs")
        if (coverage["kev_snapshot_id"] != kev["snapshot_id"]
                or coverage["epss_snapshot_id"] != epss["snapshot_id"]
                or population["epss_snapshot_id"] != epss["snapshot_id"]
                or any(b["epss_snapshot_id"] != epss["snapshot_id"] for b in bands)):
            raise ExportError("Analytical snapshot lineage mismatch")
        total = coverage["denominator_total_kev"]
        matched = coverage["numerator_matched_kev"]
        missing = coverage["unmatched_kev"]
        scored = population["scored_cve_count"]
        if any(not isinstance(v, int) or v < 0 for v in (total, matched, missing, scored)):
            raise ExportError("Invalid negative or noninteger population")
        if total != matched + missing or total != kev["row_count"]:
            raise ExportError("KEV coverage reconciliation failed")
        if scored != epss["row_count"]:
            raise ExportError("EPSS source population mismatch")
        pct = coverage["coverage_percent"]
        if total == 0:
            if pct is not None:
                raise ExportError("Undefined KEV coverage must be NULL")
        elif pct is None or not math.isclose(pct, 100 * matched / total, abs_tol=1e-8):
            raise ExportError("Coverage percentage mismatch")
        if [b["band_order"] for b in bands] != list(range(1, 6)):
            raise ExportError("Score bands must be numbered 1 to 5")
        if any(b["metric_id"] != "M04" or b["denominator_scored_cves"] != scored
               or b["cve_count"] < 0 for b in bands):
            raise ExportError("Invalid score band denominator or label")
        if sum(b["cve_count"] for b in bands) != scored:
            raise ExportError("EPSS score bands do not reconcile")
        if any((b["population_percent"] is not None) if scored == 0 else
               (b["population_percent"] is None or not math.isclose(
                   b["population_percent"], 100 * b["cve_count"] / scored, abs_tol=1e-8))
               for b in bands):
            raise ExportError("EPSS band percentages do not reconcile")
        if any(coverage[k] != kev["source_date"] for k in ("kev_catalog_date_released",)):
            raise ExportError("KEV source date mismatch")
        if (coverage["epss_source_date"] != epss["source_date"]
                or population["epss_source_date"] != epss["source_date"]
                or any(b["epss_source_date"] != epss["source_date"] for b in bands)):
            raise ExportError("EPSS source date mismatch")
        return {
            "source_snapshots": sources,
            "data_kind": ("synthetic_fixture" if epss["model_version"] == "v-ci-synthetic"
                          else "archived_source_snapshots"),
            "validation": {"kev_total": total, "kev_matched": matched,
                           "kev_unmatched": missing, "epss_scored_total": scored},
        }
    except (duckdb.Error, KeyError, TypeError) as exc:
        raise ExportError(f"Warehouse analytical export prerequisites failed: {exc}") from exc


def export_bundle(database: Path, output: Path) -> dict[str, object]:
    """Publish a new immutable directory after checks; never replace existing output."""
    if not database.is_file():
        raise ExportError(f"Existing DuckDB database required: {database}")
    if output.exists() or output.is_symlink():
        raise ExportError(f"Refusing to overwrite existing export: {output}")
    if not output.parent.is_dir():
        raise ExportError(f"Export parent directory must exist: {output.parent}")
    stage = output.parent / (".patchline-export-" + uuid.uuid4().hex)
    stage.mkdir()
    try:
        with duckdb.connect(str(database), read_only=True) as con:
            info = _validate(con)
            artifacts = []
            for name, relation, ordering in MODELS:
                columns, rows = _query(con, f"SELECT * FROM {relation} ORDER BY {ordering}")
                csv_path = stage / f"{name}.csv"
                with csv_path.open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
                    writer.writeheader()
                    writer.writerows(rows)
                json_path = stage / f"{name}.json"
                json_path.write_text(json.dumps(rows, sort_keys=True, ensure_ascii=False,
                                                indent=2, allow_nan=False) + "\n", encoding="utf-8")
                parquet_path = stage / f"{name}.parquet"
                # Source identifiers are module constants, not user-provided SQL.
                escaped = str(parquet_path).replace("'", "''")
                con.execute(f"COPY (SELECT * FROM {relation} ORDER BY {ordering}) "
                            f"TO '{escaped}' (FORMAT PARQUET, COMPRESSION ZSTD)")
                for file in (csv_path, json_path, parquet_path):
                    artifacts.append({"path": file.name, "sha256": _sha256(file),
                                      "bytes": file.stat().st_size, "rows": len(rows),
                                      "columns": columns, "model": name})
            manifest = {"schema_id": SCHEMA_ID, "data_kind": info["data_kind"],
                        "source_snapshots": info["source_snapshots"],
                        "validation": info["validation"], "artifacts": artifacts,
                        "notes": ["Local archived-source snapshot pair; not necessarily current.",
                                  "EPSS is a probability estimate, not observed exploitation.",
                                  "Fixture results are synthetic and not empirical findings."]}
            (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True,
                                ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        if output.exists() or output.is_symlink():
            raise ExportError("Export path appeared during staging; refusing overwrite")
        os.rename(stage, output)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def verify_bundle(output: Path) -> dict[str, object]:
    """Validate the immutable file manifest and refuse missing or extra artifacts."""
    if not output.is_dir() or output.is_symlink():
        raise ExportError("Export bundle directory missing or symlinked")
    manifest_file = output / "manifest.json"
    if not manifest_file.is_file() or manifest_file.is_symlink():
        raise ExportError("Missing export manifest")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if manifest["schema_id"] != SCHEMA_ID:
            raise ExportError("Unexpected export manifest schema")
        artifacts = manifest["artifacts"]
        expected = {"manifest.json"} | {f"{name}.{ext}" for name, _, _ in MODELS
                                          for ext in ("csv", "json", "parquet")}
        if {a["path"] for a in artifacts} | {"manifest.json"} != expected:
            raise ExportError("Missing or unexpected manifest artifacts")
        if {p.name for p in output.iterdir()} != expected:
            raise ExportError("Unexpected files in export directory")
        for item in artifacts:
            file = output / item["path"]
            if file.is_symlink() or not file.is_file() or file.stat().st_size != item["bytes"]:
                raise ExportError(f"Missing or altered export: {item['path']}")
            if _sha256(file) != item["sha256"]:
                raise ExportError(f"Export digest mismatch: {item['path']}")
            if item["path"].endswith(".json"):
                rows = json.loads(file.read_text(encoding="utf-8"))
                if len(rows) != item["rows"] or any(set(r) != set(item["columns"]) for r in rows):
                    raise ExportError(f"JSON record contract mismatch: {item['path']}")
        return manifest
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, ExportError):
            raise
        raise ExportError(f"Invalid export manifest: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    """CLI for deterministic analytics bundle publication and verification."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="Export validated DuckDB marts")
    create.add_argument("--database", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify", help="Verify exported artifacts and manifest")
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = (export_bundle(args.database, args.output) if args.command == "create"
                  else verify_bundle(args.output))
    except (ExportError, OSError, duckdb.Error) as exc:
        print(f"Export {args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok", "action": args.command,
                      "data_kind": result["data_kind"],
                      "artifacts": len(result["artifacts"]),
                      "validation": result["validation"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
