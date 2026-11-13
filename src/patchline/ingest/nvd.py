"""Explicit offline NVD CVE API 2.0 page validation and immutable archival.

EA-03A1 deliberately handles *one* response page, never a complete NVD corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchline.ingest.kev import KEVIngestionError, _atomic_write_new

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FORMAT_VERSION = "patchline.nvd-page-manifest.v1"
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
MAX_PAGE_BYTES = 20 * 1024 * 1024
MAX_PAGE_RECORDS = 2_000


class NVDIngestionError(ValueError):
    """An untrusted NVD page or existing archived page failed validation."""


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise NVDIngestionError(f"{name} must be an integer >= {minimum}")
    return value


def _nvd_timestamp(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "T" not in value:
        raise NVDIngestionError(f"Invalid {name} timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NVDIngestionError(f"Invalid {name} timestamp") from exc
    # The NVD endpoint commonly omits an explicit timezone: preserve its exact value.
    return value


def validate_nvd_page(payload: bytes) -> dict[str, Any]:
    """Validate one NVD CVE 2.0 page and return strictly page-scoped metadata.

    Does not certify completeness of a multi-page API query or CVE correctness.
    """
    if not payload or len(payload) > MAX_PAGE_BYTES:
        raise NVDIngestionError("NVD page is empty or exceeds the size limit")
    try:
        result = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NVDIngestionError("NVD page is not valid UTF-8 JSON") from exc
    if not isinstance(result, dict):
        raise NVDIngestionError("NVD page must be an object")
    if result.get("format") != "NVD_CVE" or result.get("version") != "2.0":
        raise NVDIngestionError("Unexpected NVD format or API version")
    timestamp = _nvd_timestamp(result.get("timestamp"), "NVD response")
    page_limit = _integer(result.get("resultsPerPage"), "resultsPerPage", minimum=1)
    start_index = _integer(result.get("startIndex"), "startIndex")
    total_results = _integer(result.get("totalResults"), "totalResults")
    rows = result.get("vulnerabilities")
    if not isinstance(rows, list):
        raise NVDIngestionError("NVD vulnerabilities must be a list")
    if not rows:
        raise NVDIngestionError("NVD page contains no CVE records")
    if page_limit > MAX_PAGE_RECORDS or len(rows) > MAX_PAGE_RECORDS:
        raise NVDIngestionError("NVD page exceeds the maximum record limit")
    if len(rows) > page_limit or start_index + len(rows) > total_results:
        raise NVDIngestionError("NVD pagination metadata disagrees with record count")

    seen: set[str] = set()
    counts: dict[str, int] = {}
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("cve"), dict):
            raise NVDIngestionError(f"Invalid vulnerability wrapper at row {position}")
        cve = row["cve"]
        identifier = cve.get("id")
        if not isinstance(identifier, str) or not CVE_RE.fullmatch(identifier):
            raise NVDIngestionError(f"Invalid CVE identifier at row {position}")
        if identifier in seen:
            raise NVDIngestionError(f"Duplicate CVE identifier: {identifier}")
        seen.add(identifier)
        _nvd_timestamp(cve.get("published"), f"published for {identifier}")
        _nvd_timestamp(cve.get("lastModified"), f"lastModified for {identifier}")
        status = cve.get("vulnStatus")
        if not isinstance(status, str) or not status.strip():
            raise NVDIngestionError(f"Missing NVD status for {identifier}")
        counts[status] = counts.get(status, 0) + 1
        if not isinstance(cve.get("descriptions"), list):
            raise NVDIngestionError(f"Missing descriptions array for {identifier}")
        for field, expected_type in (
            ("metrics", dict),
            ("weaknesses", list),
            ("configurations", list),
            ("references", list),
        ):
            if field in cve and not isinstance(cve[field], expected_type):
                raise NVDIngestionError(f"Unexpected {field} type for {identifier}")

    return {
        "api_format": "NVD_CVE",
        "api_version": "2.0",
        "response_timestamp": timestamp,
        "start_index": start_index,
        "results_per_page": page_limit,
        "reported_total_results": total_results,
        "row_count": len(rows),
        "status_counts": dict(sorted(counts.items())),
        "coverage_scope": "single_response_page_only",
    }


def archive_nvd_page(data_dir: Path, *, page_bytes: bytes) -> dict[str, Any]:
    """Archive exactly one validated NVD response without overwriting prior bytes."""
    metadata = validate_nvd_page(page_bytes)
    digest = hashlib.sha256(page_bytes).hexdigest()
    folder = data_dir / "raw" / "nvd" / digest
    source_path = folder / "page.json"
    manifest_path = folder / "manifest.json"
    manifest: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "source": "NIST NVD CVE API 2.0",
        "endpoint": NVD_CVE_API,
        "acquisition": "offline_supplied_page",
        "query_parameters_verified": False,
        "snapshot_id": digest,
        "page_sha256": digest,
        "page_bytes": len(page_bytes),
        "retrieved_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "validation": "passed",
        **metadata,
    }
    if manifest_path.exists():
        try:
            old = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise NVDIngestionError("Existing NVD manifest is not valid JSON") from exc
        if not isinstance(old, dict):
            raise NVDIngestionError("Existing NVD manifest must be an object")
        if set(old) != set(manifest):
            raise NVDIngestionError("Existing NVD manifest field inventory mismatch")
        for key, value in manifest.items():
            if key != "retrieved_at_utc" and old.get(key) != value:
                raise NVDIngestionError(f"Existing NVD manifest mismatch: {key}")
        saved_time = old.get("retrieved_at_utc")
        if not isinstance(saved_time, str) or not saved_time.endswith("Z"):
            raise NVDIngestionError("Invalid archived retrieval timestamp")
        _nvd_timestamp(saved_time, "archived retrieval")
        if not source_path.is_file():
            raise NVDIngestionError("Existing archived NVD page is missing")
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != digest:
            raise NVDIngestionError("Archived NVD page hash mismatch")
        return {**old, "status": "skipped_existing", "snapshot_path": str(folder)}

    # The manifest is the completion marker, after the immutable source bytes.
    try:
        _atomic_write_new(source_path, page_bytes)
        _atomic_write_new(
            manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
    except KEVIngestionError as exc:
        raise NVDIngestionError(str(exc)) from exc
    return {**manifest, "status": "ingested", "snapshot_path": str(folder)}


def main(argv: list[str] | None = None) -> int:
    """Explicit offline import. EA-03A1 intentionally does not download from NVD."""
    parser = argparse.ArgumentParser(description="Archive one previously obtained NVD CVE API page")
    parser.add_argument("--file", type=Path, required=True, help="NVD CVE API 2.0 JSON page")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args(argv)
    try:
        if not args.file.is_file() or args.file.stat().st_size > MAX_PAGE_BYTES:
            raise NVDIngestionError("Source file missing or exceeds page size limit")
        result = archive_nvd_page(args.data_dir, page_bytes=args.file.read_bytes())
    except (NVDIngestionError, OSError) as exc:
        print(f"NVD page archival failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
