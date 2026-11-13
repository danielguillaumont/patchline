"""Plan a reproducible archive-pair analysis without writing run state."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from patchline.warehouse.build import WarehouseError, _validated_inputs

SCHEMA_ID = "patchline.batch-plan.v1"
ANALYTICS_CONTRACT = "patchline.analytics-export.v2"
SNAPSHOT_ID = re.compile(r"[0-9a-f]{64}\Z")


class BatchPlanError(ValueError):
    """An archive pair or proposed run workspace cannot be safely planned."""


def _source_info(manifest: dict[str, Any], source: str) -> dict[str, object]:
    """Return explicit provenance rather than implied latest-source metadata."""
    date_key = "catalog_date_released" if source == "kev" else "score_date"
    return {
        "snapshot_id": manifest["snapshot_id"],
        "source_date": manifest[date_key],
        "retrieved_at_utc": manifest["retrieved_at_utc"],
        "row_count": manifest["row_count"],
        "model_version": manifest.get("model_version") if source == "epss" else None,
    }


def plan_batch(data_dir: Path, *, kev_snapshot: str, epss_snapshot: str) -> dict[str, object]:
    """Fully revalidate archived inputs and preview non-overwriting run paths.

    Run identity depends only on version, contract and immutable source hashes.
    This function does not create directories, run dbt, or persist a plan.
    """
    if not SNAPSHOT_ID.fullmatch(kev_snapshot):
        raise BatchPlanError("KEV snapshot must be a lowercase 64-character SHA-256 ID")
    if not SNAPSHOT_ID.fullmatch(epss_snapshot):
        raise BatchPlanError("EPSS snapshot must be a lowercase 64-character SHA-256 ID")
    if not data_dir.is_dir():
        raise BatchPlanError("Data directory does not exist")

    # Reuse warehouse validation: both source manifests, all archive digests,
    # re-parsed KEV JSON and EPSS CSV, exact row counts and source metadata.
    try:
        kev, epss, _, _ = _validated_inputs(data_dir, kev_snapshot, epss_snapshot)
    except (WarehouseError, OSError, KeyError, TypeError, ValueError) as exc:
        raise BatchPlanError(f"Archived source-pair validation failed: {exc}") from exc

    identity = {
        "schema_id": SCHEMA_ID,
        "analytics_contract": ANALYTICS_CONTRACT,
        "kev_snapshot_id": kev_snapshot,
        "epss_snapshot_id": epss_snapshot,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    run_id = "batch-" + hashlib.sha256(canonical).hexdigest()
    root = data_dir.resolve() / "runs"
    run_dir = root / run_id

    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise BatchPlanError("Run workspace root is not a normal directory")
    if run_dir.exists() or run_dir.is_symlink():
        raise BatchPlanError("Run workspace already exists; refusing a potential overwrite")

    return {
        "schema_id": SCHEMA_ID,
        "status": "planned_only",
        "persisted": False,
        "run_id": run_id,
        "analytics_contract": ANALYTICS_CONTRACT,
        "sources": {"kev": _source_info(kev, "kev"), "epss": _source_info(epss, "epss")},
        "targets": {
            "run_directory": str(run_dir),
            "warehouse": str(run_dir / "warehouse" / "patchline.duckdb"),
            "v2_export": str(run_dir / "exports" / "v2"),
        },
        "stages": {"warehouse": "not_started", "dbt": "not_started", "export": "not_started"},
    }
