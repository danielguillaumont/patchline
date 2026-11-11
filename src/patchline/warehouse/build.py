"""Build a source-traceable DuckDB warehouse from archived, validated snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

from patchline.ingest.epss import validate_epss
from patchline.ingest.kev import validate_kev


class WarehouseError(ValueError):
    """Invalid source snapshot or unsafe warehouse publication."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot(data_dir: Path, source: str, snapshot_id: str | None) -> Path:
    root = data_dir / "raw" / source
    if snapshot_id is not None:
        if len(snapshot_id) != 64 or any(ch not in "0123456789abcdef" for ch in snapshot_id):
            raise WarehouseError(f"Invalid {source} snapshot identifier")
        path = root / snapshot_id
    else:
        if not root.is_dir():
            raise WarehouseError(f"No archived {source} snapshot exists")
        choices = sorted(path for path in root.iterdir() if path.is_dir())
        if len(choices) != 1:
            raise WarehouseError(
                f"Expected exactly one {source} snapshot, found {len(choices)}; "
                "select one explicitly by hash"
            )
        path = choices[0]
    if not path.is_dir():
        raise WarehouseError(f"Missing {source} snapshot: {path.name}")
    return path


def _read_manifest(folder: Path, source: str) -> dict[str, Any]:
    path = folder / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise WarehouseError(f"Unreadable {source} manifest") from exc
    if not isinstance(manifest, dict) or manifest.get("validation") != "passed":
        raise WarehouseError(f"Invalid or unvalidated {source} manifest")
    if manifest.get("snapshot_id") != folder.name:
        raise WarehouseError(f"{source} manifest snapshot ID mismatch")
    return manifest


def _validated_inputs(
    data_dir: Path, kev_id: str | None, epss_id: str | None
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    kev_folder = _snapshot(data_dir, "kev", kev_id)
    epss_folder = _snapshot(data_dir, "epss", epss_id)
    km = _read_manifest(kev_folder, "KEV")
    em = _read_manifest(epss_folder, "EPSS")
    try:
        catalog_bytes = (kev_folder / "catalog.json").read_bytes()
        schema_bytes = (kev_folder / "schema.json").read_bytes()
        epss_bytes = (epss_folder / "scores.csv.gz").read_bytes()
    except OSError as exc:
        raise WarehouseError("Missing or unreadable archived source file") from exc
    expected_hashes = (
        (catalog_bytes, km.get("catalog_sha256"), "KEV catalog"),
        (schema_bytes, km.get("schema_sha256"), "KEV schema"),
        (epss_bytes, em.get("compressed_sha256"), "EPSS gzip"),
    )
    for content, expected, label in expected_hashes:
        if not isinstance(expected, str) or _sha256(content) != expected:
            raise WarehouseError(f"{label} archive SHA-256 mismatch")
    if km["catalog_sha256"] != kev_folder.name or em["compressed_sha256"] != epss_folder.name:
        raise WarehouseError("Content-addressed snapshot directory mismatch")
    try:
        catalog = validate_kev(catalog_bytes, schema_bytes)
        epss = validate_epss(epss_bytes)
    except (ValueError, KeyError, TypeError) as exc:
        raise WarehouseError(f"Source revalidation failed: {exc}") from exc
    if (
        km.get("row_count") != len(catalog["vulnerabilities"])
        or km.get("catalog_version") != catalog["catalogVersion"]
        or km.get("catalog_date_released") != catalog["dateReleased"]
    ):
        raise WarehouseError("KEV manifest metadata mismatch")
    if any(em.get(key) != epss[key] for key in ("row_count", "model_version", "score_date")):
        raise WarehouseError("EPSS manifest metadata mismatch")
    return km, em, catalog, epss_folder / "scores.csv.gz"


def build_warehouse(
    data_dir: Path,
    output: Path,
    *,
    kev_snapshot_id: str | None = None,
    epss_snapshot_id: str | None = None,
) -> dict[str, Any]:
    """Build a new database, verify row counts, and publish without overwriting.

    Snapshot inputs are verified before any database is written. Publication uses
    an atomic hard link, so a preexisting database is never silently replaced.
    """
    if output.exists():
        raise WarehouseError(f"Warehouse already exists; refusing overwrite: {output}")
    km, em, catalog, epss_path = _validated_inputs(data_dir, kev_snapshot_id, epss_snapshot_id)

    # Imported here so source validation can run without the optional warehouse dependency.
    import duckdb

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".patchline-warehouse-", suffix=".duckdb", dir=output.parent
    )
    os.close(descriptor)
    temp_path = Path(temporary)
    temp_path.unlink()  # DuckDB creates its database on connect.
    connection = None
    try:
        connection = duckdb.connect(str(temp_path))
        connection.execute("BEGIN TRANSACTION")
        connection.execute(
            """CREATE TABLE source_snapshots (
                source VARCHAR NOT NULL PRIMARY KEY,
                snapshot_id VARCHAR NOT NULL,
                retrieved_at_utc VARCHAR NOT NULL,
                source_date VARCHAR NOT NULL,
                model_version VARCHAR,
                row_count BIGINT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE raw_kev_snapshot (
                snapshot_id VARCHAR NOT NULL,
                cve_id VARCHAR NOT NULL,
                date_added DATE NOT NULL,
                due_date DATE NOT NULL,
                vendor_project VARCHAR,
                product VARCHAR,
                vulnerability_name VARCHAR,
                known_ransomware_campaign_use VARCHAR,
                PRIMARY KEY (snapshot_id, cve_id)
            )"""
        )
        connection.execute(
            """CREATE TABLE raw_epss_daily (
                snapshot_id VARCHAR NOT NULL,
                score_date DATE NOT NULL,
                model_version VARCHAR NOT NULL,
                cve_id VARCHAR NOT NULL,
                epss DOUBLE NOT NULL,
                percentile DOUBLE NOT NULL,
                PRIMARY KEY (snapshot_id, cve_id)
            )"""
        )
        kev_rows = [
            (
                km["snapshot_id"], row["cveID"], date.fromisoformat(row["dateAdded"]),
                date.fromisoformat(row["dueDate"]), row.get("vendorProject"),
                row.get("product"), row.get("vulnerabilityName"),
                row.get("knownRansomwareCampaignUse"),
            )
            for row in catalog["vulnerabilities"]
        ]
        connection.executemany(
            "INSERT INTO raw_kev_snapshot VALUES (?, ?, ?, ?, ?, ?, ?, ?)", kev_rows
        )
        # DuckDB reads compressed CSV natively, avoiding 400k+ Python row inserts.
        # Exact source bytes were already revalidated before reaching this step.
        connection.execute(
            """INSERT INTO raw_epss_daily
               SELECT ?, CAST(? AS DATE), ?, cve,
                      CAST(epss AS DOUBLE), CAST(percentile AS DOUBLE)
               FROM read_csv(?, header=true, skip=1, compression='gzip',
                    columns={'cve':'VARCHAR','epss':'VARCHAR','percentile':'VARCHAR'})""",
            [em["snapshot_id"], em["score_date"][:10], em["model_version"], str(epss_path)],
        )
        connection.executemany(
            "INSERT INTO source_snapshots VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("kev", km["snapshot_id"], km["retrieved_at_utc"],
                 km["catalog_date_released"], None, km["row_count"]),
                ("epss", em["snapshot_id"], em["retrieved_at_utc"],
                 em["score_date"], em["model_version"], em["row_count"]),
            ],
        )
        kev_count = connection.execute("SELECT COUNT(*) FROM raw_kev_snapshot").fetchone()[0]
        epss_count = connection.execute("SELECT COUNT(*) FROM raw_epss_daily").fetchone()[0]
        if kev_count != km["row_count"] or epss_count != em["row_count"]:
            raise WarehouseError("Warehouse/source row-count reconciliation failed")
        connection.execute("COMMIT")
        connection.close()
        connection = None
        # No overwrite: fail if another process published between initial check and now.
        try:
            os.link(temp_path, output)
        except FileExistsError as exc:
            raise WarehouseError("Warehouse appeared during build; refusing overwrite") from exc
        return {
            "status": "built", "database_path": str(output),
            "kev_snapshot_id": km["snapshot_id"], "epss_snapshot_id": em["snapshot_id"],
            "kev_rows": kev_count, "epss_rows": epss_count,
            "score_date": em["score_date"], "model_version": em["model_version"],
        }
    except Exception:
        if connection is not None:
            connection.close()
        raise
    finally:
        temp_path.unlink(missing_ok=True)
