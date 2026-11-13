"""EA-03A3A: offline normalization of a validated, archived NVD response page.

This is NOT a query-wide snapshot, warehouse model, scoring system, or public export.
All NVD timestamp strings remain unchanged (the API may omit timezone offsets).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from patchline.ingest.kev import KEVIngestionError, _atomic_write_new
from patchline.ingest.nvd import (
    FORMAT_VERSION as SOURCE_FORMAT_VERSION,
)
from patchline.ingest.nvd import (
    NVDIngestionError,
    validate_nvd_page,
)

NORMALIZED_FORMAT_VERSION = "patchline.nvd-normalized-page.v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CVSS_VERSIONS = {
    "cvssMetricV2": "2.0",
    "cvssMetricV30": "3.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV40": "4.0",
}


class NVDNormalizationError(ValueError):
    """Normalization could not preserve or verify an NVD source contract."""


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NVDNormalizationError(f"{field} must be an object")
    return value


def _optional_text(value: Any, field: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise NVDNormalizationError(f"{field} must be text or null")
    return value


def _score(value: Any, field: str) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 10:
        raise NVDNormalizationError(f"{field} must be a finite score between 0 and 10")
    return float(value)


def _records(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise NVDNormalizationError(f"{field} must be an array")
    for index, item in enumerate(value):
        _object(item, f"{field}[{index}]")
    return value


def _descriptions(cve: dict[str, Any], cve_id: str) -> tuple[list[dict[str, str]], str | None]:
    raw = _records(cve["descriptions"], f"{cve_id}.descriptions")
    result = []
    english = None
    for index, item in enumerate(raw):
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not lang or not isinstance(value, str):
            raise NVDNormalizationError(f"Invalid description {index} for {cve_id}")
        # Keep every language entry; never translate or invent English content.
        result.append(deepcopy(item))
        if lang.lower() == "en" and english is None:
            english = value
    return result, english


def _metrics(cve: dict[str, Any], cve_id: str) -> list[dict[str, Any]]:
    source_metrics = _object(cve.get("metrics", {}), f"{cve_id}.metrics")
    normalized = []
    for key, expected_version in CVSS_VERSIONS.items():
        if key not in source_metrics:
            continue
        entries = _records(source_metrics[key], f"{cve_id}.metrics.{key}")
        for index, entry in enumerate(entries):
            context = f"{cve_id}.{key}[{index}]"
            data = _object(entry.get("cvssData"), f"{context}.cvssData")
            if data.get("version") != expected_version:
                raise NVDNormalizationError(f"{context}: CVSS version does not match metric key")
            source = _optional_text(entry.get("source"), f"{context}.source")
            metric_type = _optional_text(entry.get("type"), f"{context}.type")
            vector = _optional_text(data.get("vectorString"), f"{context}.vectorString")
            severity = _optional_text(
                data.get("baseSeverity", entry.get("baseSeverity")),
                f"{context}.baseSeverity",
            )
            # A missing score stays null, never a zero or an inferred value.
            normalized.append(
                {
                    "metric_key": key,
                    "cvss_version": expected_version,
                    "source": source,
                    "type": metric_type,
                    "vector_string": vector,
                    "base_score": _score(data.get("baseScore"), f"{context}.baseScore"),
                    "base_severity": severity,
                    # Preserve version-specific fields for subsequent modeling.
                    "source_metric": deepcopy(entry),
                }
            )
    unknown = set(source_metrics) - set(CVSS_VERSIONS)
    if unknown:
        raise NVDNormalizationError(f"{cve_id}: unsupported metrics keys: {sorted(unknown)}")
    return normalized


def _normalize_record(cve: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve["id"]  # validate_nvd_page validates identifier and mandatory fields.
    descriptions, english = _descriptions(cve, cve_id)
    metrics = _metrics(cve, cve_id)
    weaknesses = deepcopy(_records(cve.get("weaknesses", []), f"{cve_id}.weaknesses"))
    configurations = deepcopy(_records(cve.get("configurations", []), f"{cve_id}.configurations"))
    references = deepcopy(_records(cve.get("references", []), f"{cve_id}.references"))
    source_id = _optional_text(cve.get("sourceIdentifier"), f"{cve_id}.sourceIdentifier")
    return {
        "cve_id": cve_id,
        "source_identifier": source_id,
        "vuln_status": cve["vulnStatus"],
        "published_source_timestamp": cve["published"],
        "modified_source_timestamp": cve["lastModified"],
        "description_en": english,
        "descriptions": descriptions,
        "cvss_metrics": metrics,
        "weaknesses": weaknesses,
        # Preserve nested AND/OR, negate and CPE version constraints verbatim.
        # No assertion of affected product, asset exposure or exploitability.
        "configurations": configurations,
        "references": references,
        "missing": {
            "english_description": english is None,
            "cvss_metrics": not metrics,
            "weaknesses": not weaknesses,
            "configurations": not configurations,
            "references": not references,
        },
    }


def normalize_nvd_page(page_bytes: bytes) -> dict[str, Any]:
    """Return stable typed record projections from ONE source-validated page."""
    try:
        metadata = validate_nvd_page(page_bytes)
    except NVDIngestionError as exc:
        raise NVDNormalizationError(f"Invalid NVD response page: {exc}") from exc
    page = json.loads(page_bytes)
    records = [_normalize_record(wrapper["cve"]) for wrapper in page["vulnerabilities"]]
    return {
        "format_version": NORMALIZED_FORMAT_VERSION,
        "source": "NIST NVD CVE API 2.0",
        "source_page_sha256": hashlib.sha256(page_bytes).hexdigest(),
        "source_response_timestamp": metadata["response_timestamp"],
        "source_start_index": metadata["start_index"],
        "source_results_per_page": metadata["results_per_page"],
        "source_reported_total_results": metadata["reported_total_results"],
        "record_count": len(records),
        "records": records,
        "scope": "one_verified_archived_page_only",
        "point_in_time_consistency_verified": False,
        "global_nvd_completeness_attested": False,
        "organization_asset_exposure_known": False,
        "source_origin_independently_verified": False,
    }


def _json_bytes(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def normalize_archived_nvd_page(data_dir: Path, *, snapshot_id: str) -> dict[str, Any]:
    """Verify immutable raw archive before writing an idempotent local projection."""
    if not isinstance(snapshot_id, str) or not SHA256_PATTERN.fullmatch(snapshot_id):
        raise NVDNormalizationError("snapshot_id must be lowercase SHA-256")
    archive = data_dir / "raw" / "nvd" / snapshot_id
    page_path = archive / "page.json"
    manifest_path = archive / "manifest.json"
    if not page_path.is_file() or not manifest_path.is_file():
        raise NVDNormalizationError("NVD archived page or manifest is missing")
    page_bytes = page_path.read_bytes()
    if hashlib.sha256(page_bytes).hexdigest() != snapshot_id:
        raise NVDNormalizationError("NVD archived page SHA-256 mismatch")
    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = _object(json.loads(manifest_bytes), "source manifest")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NVDNormalizationError("Invalid NVD source manifest JSON") from exc
    normalized = normalize_nvd_page(page_bytes)
    metadata = validate_nvd_page(page_bytes)
    required_fields = {
        "format_version": SOURCE_FORMAT_VERSION,
        "snapshot_id": snapshot_id,
        "page_sha256": snapshot_id,
        "page_bytes": len(page_bytes),
        "validation": "passed",
        **metadata,
    }
    for field, expected in required_fields.items():
        if manifest.get(field) != expected or type(manifest.get(field)) is not type(expected):
            raise NVDNormalizationError(f"NVD source manifest mismatch: {field}")
    normalized["source_archive_manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    normalized["source_page_relative_path"] = f"raw/nvd/{snapshot_id}/page.json"
    normalized["source_manifest_relative_path"] = f"raw/nvd/{snapshot_id}/manifest.json"
    destination = data_dir / "normalized" / "nvd-pages" / snapshot_id / "normalized.json"
    content = _json_bytes(normalized)
    existed = destination.is_file()
    try:
        _atomic_write_new(destination, content)
    except KEVIngestionError as exc:
        raise NVDNormalizationError(f"Normalized page collision: {exc}") from exc
    return {
        "status": "verified_existing" if existed else "normalized",
        "format_version": NORMALIZED_FORMAT_VERSION,
        "source_page_sha256": snapshot_id,
        "normalized_sha256": hashlib.sha256(content).hexdigest(),
        "records": normalized["record_count"],
        "output_path": str(destination),
        "scope": normalized["scope"],
        "point_in_time_consistency_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline NVD archived-page normalization")
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args(argv)
    try:
        result = normalize_archived_nvd_page(args.data_dir, snapshot_id=args.snapshot_id)
    except (NVDNormalizationError, OSError) as exc:
        print(f"NVD normalization failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
