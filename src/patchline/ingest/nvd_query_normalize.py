"""EA-03A3B: verify and normalize ONE completed NVD query's archived pages.

All work is offline. Pagination reconciliation is not a point-in-time snapshot;
conflicting/duplicate CVE IDs fail closed, rather than being silently resolved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from patchline.ingest.kev import KEVIngestionError, _atomic_write_new
from patchline.ingest.nvd import (
    FORMAT_VERSION as RAW_PAGE_VERSION,
)
from patchline.ingest.nvd import (
    NVDIngestionError,
    validate_nvd_page,
)
from patchline.ingest.nvd_acquire import NVDAcquisitionError, _utc_timestamp, build_nvd_request
from patchline.ingest.nvd_normalize import NVDNormalizationError, normalize_nvd_page
from patchline.ingest.nvd_pagination import (
    MAX_QUERY_BYTES,
    MAX_QUERY_PAGES,
    QUERY_FORMAT_VERSION,
)

QUERY_NORMALIZED_VERSION = "patchline.nvd-normalized-query.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class NVDQueryNormalizationError(ValueError):
    """A completed query could not be verified or normalized safely."""


def _fail(message: str) -> None:
    raise NVDQueryNormalizationError(message)


def _int(value: Any, field: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(f"{field} must be an integer >= {minimum}")
    return value


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{field} must be lowercase SHA-256")
    return value


def _json_bytes(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _read_json(path: Path, field: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file():
        _fail(f"{field} is missing")
    content = path.read_bytes()
    try:
        result = json.loads(content.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise NVDQueryNormalizationError(f"{field} contains invalid JSON") from exc
    if not isinstance(result, dict):
        _fail(f"{field} must be a JSON object")
    return result, content


def _verify_query_manifest(manifest: dict[str, Any], query_id: str) -> dict[str, Any]:
    if manifest.get("format_version") != QUERY_FORMAT_VERSION:
        _fail("Unsupported NVD query manifest version")
    if manifest.get("query_id") != query_id:
        _fail("NVD query ID mismatch")
    if manifest.get("source") != "NIST NVD CVE API 2.0":
        _fail("Unexpected NVD query source")
    if manifest.get("acquisition_type") != "explicit_bounded_https_paginated_query":
        _fail("Unexpected query acquisition type")
    if (manifest.get("scope") != "query_pagination_vs_reported_total_only"
            or manifest.get("pagination_reconciled") is not True
            or manifest.get("point_in_time_consistency_verified") is not False
            or manifest.get("global_nvd_completeness_attested") is not False
            or manifest.get("zero_result_queries_supported") is not False):
        _fail("NVD query scope or completeness flags mismatch")
    try:
        _utc_timestamp(manifest.get("acquired_at_utc"), "NVD query acquisition timestamp")
    except NVDAcquisitionError as exc:
        raise NVDQueryNormalizationError(str(exc)) from exc
    parameters = manifest.get("request_parameters")
    if not isinstance(parameters, dict):
        _fail("NVD query parameters missing")
    try:
        approved = build_nvd_request(
            cve_id=parameters.get("cveId"),
            last_mod_start=parameters.get("lastModStartDate"),
            last_mod_end=parameters.get("lastModEndDate"),
            results_per_page=int(parameters.get("resultsPerPage", -1)),
        )
    except (TypeError, ValueError) as exc:
        raise NVDQueryNormalizationError("Invalid NVD query parameters") from exc
    if (parameters != approved["parameters"]
            or manifest.get("query_mode") != approved["query_mode"]
            or manifest.get("first_page_request_url") != approved["url"]):
        _fail("Query parameters differ from allowlisted request")
    query_sha = hashlib.sha256(approved["url"].encode("utf-8")).hexdigest()
    if manifest.get("query_sha256") != query_sha:
        _fail("NVD request URL SHA-256 mismatch")
    requested_pages = _int(manifest.get("requested_max_pages"), "requested_max_pages", 1)
    if requested_pages > MAX_QUERY_PAGES:
        _fail("NVD query exceeds max page budget")
    pages = manifest.get("pages")
    if not isinstance(pages, list) or not pages or len(pages) > requested_pages:
        _fail("NVD query pages missing or exceed budget")
    if _int(manifest.get("pages_retrieved"), "pages_retrieved", 1) != len(pages):
        _fail("NVD pages retrieved count mismatch")
    total = _int(manifest.get("reported_total_results"), "reported_total_results", 1)
    if _int(manifest.get("unique_cve_count"), "unique_cve_count", 1) != total:
        _fail("NVD unique CVE count mismatch")
    if total > requested_pages * int(parameters["resultsPerPage"]):
        _fail("NVD total exceeds requested page budget")
    response_bytes = _int(manifest.get("total_response_bytes"), "total_response_bytes", 1)
    if response_bytes > MAX_QUERY_BYTES:
        _fail("NVD query response size exceeds bound")
    page_hashes = []
    for page in pages:
        if not isinstance(page, dict):
            _fail("NVD page manifest entry must be an object")
        page_hashes.append(_sha(page.get("sha256"), "NVD page digest"))
    calculated_id = hashlib.sha256(
        _json_bytes({"query_sha256": query_sha, "pages": page_hashes})
    ).hexdigest()
    if calculated_id != query_id:
        _fail("NVD query content-addressed ID mismatch")
    return approved


def inspect_archived_nvd_query(data_dir: Path, *, query_id: str) -> dict[str, Any]:
    """Pure verification and projection; does not write a single file."""
    _sha(query_id, "query_id")
    query_path = data_dir / "raw" / "nvd-queries" / query_id / "manifest.json"
    manifest, manifest_bytes = _read_json(query_path, "NVD query manifest")
    approved = _verify_query_manifest(manifest, query_id)
    total = manifest["reported_total_results"]
    per_page = int(approved["parameters"]["resultsPerPage"])
    expected_offset = 0
    total_bytes = 0
    seen: set[str] = set()
    all_records: list[dict[str, Any]] = []
    source_pages: list[dict[str, Any]] = []

    for page_number, page_entry in enumerate(manifest["pages"]):
        digest = page_entry["sha256"]
        raw_path = data_dir / "raw" / "nvd" / digest / "page.json"
        raw_manifest_path = data_dir / "raw" / "nvd" / digest / "manifest.json"
        if not raw_path.is_file():
            _fail(f"NVD raw page missing at index {page_number}")
        page_bytes = raw_path.read_bytes()
        if hashlib.sha256(page_bytes).hexdigest() != digest:
            _fail(f"NVD raw page SHA-256 mismatch at index {page_number}")
        try:
            metadata = validate_nvd_page(page_bytes)
            normalized = normalize_nvd_page(page_bytes)
        except (NVDIngestionError, NVDNormalizationError) as exc:
            raise NVDQueryNormalizationError(f"Invalid NVD source page {page_number}: {exc}") from exc
        archive_manifest, archive_bytes = _read_json(
            raw_manifest_path, f"NVD raw page manifest {page_number}"
        )
        expected_raw = {
            "format_version": RAW_PAGE_VERSION,
            "snapshot_id": digest,
            "page_sha256": digest,
            "page_bytes": len(page_bytes),
            "validation": "passed",
            **metadata,
        }
        for field, value in expected_raw.items():
            if archive_manifest.get(field) != value or type(archive_manifest.get(field)) is not type(value):
                _fail(f"NVD raw page manifest mismatch: {field}")
        if archive_manifest.get("source") != "NIST NVD CVE API 2.0":
            _fail("NVD raw page source mismatch")
        if archive_manifest.get("acquisition") != "offline_supplied_page":
            _fail("NVD raw page acquisition marker mismatch")
        expected_url = f"{approved['endpoint']}?" + urllib.parse.urlencode(
            sorted({**approved["parameters"], "startIndex": str(expected_offset)}.items())
        )
        expected_entry = {
            "start_index": expected_offset,
            "results_per_page": per_page,
            "row_count": min(per_page, total - expected_offset),
            "response_timestamp": metadata["response_timestamp"],
            "request_url": expected_url,
            "sha256": digest,
            "byte_count": len(page_bytes),
            "raw_page_relative_path": f"raw/nvd/{digest}/page.json",
        }
        for field, value in expected_entry.items():
            if page_entry.get(field) != value or type(page_entry.get(field)) is not type(value):
                _fail(f"NVD query page {page_number} mismatch: {field}")
        if metadata["start_index"] != expected_offset:
            _fail(f"NVD page {page_number} start index mismatch")
        if metadata["results_per_page"] != per_page:
            _fail(f"NVD page {page_number} results per page mismatch")
        if metadata["reported_total_results"] != total:
            _fail(f"NVD page {page_number} reported total mismatch")
        if metadata["row_count"] != expected_entry["row_count"]:
            _fail(f"NVD page {page_number} record count mismatch")
        total_bytes += len(page_bytes)
        for row_index, record in enumerate(normalized["records"]):
            identifier = record["cve_id"]
            if identifier in seen:
                _fail(f"Duplicate CVE across query pages: {identifier}")
            seen.add(identifier)
            all_records.append(
                {
                    **record,
                    "source_page_sha256": digest,
                    "source_page_start_index": expected_offset,
                    "source_page_record_index": row_index,
                }
            )
        source_pages.append(
            {
                "start_index": expected_offset,
                "row_count": metadata["row_count"],
                "raw_page_sha256": digest,
                "raw_manifest_sha256": hashlib.sha256(archive_bytes).hexdigest(),
            }
        )
        expected_offset += metadata["row_count"]

    if expected_offset != total or len(seen) != total:
        _fail("NVD query pages incomplete or CVE count differs")
    if total_bytes != manifest["total_response_bytes"]:
        _fail("NVD query response byte count mismatch")
    if approved["query_mode"] == "cve_id" and list(seen) != [approved["parameters"]["cveId"]]:
        _fail("NVD CVE-ID query did not return its requested identifier")

    return {
        "format_version": QUERY_NORMALIZED_VERSION,
        "source": "NIST NVD CVE API 2.0",
        "query_id": query_id,
        "query_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "query_manifest_relative_path": f"raw/nvd-queries/{query_id}/manifest.json",
        "query_mode": approved["query_mode"],
        "reported_total_results": total,
        "source_pages": source_pages,
        "record_count": len(all_records),
        "records": all_records,
        "scope": "one_paginated_query_reconciled_to_reported_total_only",
        "point_in_time_consistency_verified": False,
        "global_nvd_completeness_attested": False,
        "source_origin_independently_verified": False,
        "organization_asset_exposure_known": False,
        "duplicate_cve_resolution_performed": False,
    }


def normalize_archived_nvd_query(data_dir: Path, *, query_id: str) -> dict[str, Any]:
    """After all pages pass, atomically create or verify one immutable projection."""
    normalized = inspect_archived_nvd_query(data_dir, query_id=query_id)
    output = data_dir / "normalized" / "nvd-queries" / query_id / "normalized.json"
    content = _json_bytes(normalized)
    existed = output.is_file()
    try:
        _atomic_write_new(output, content)
    except KEVIngestionError as exc:
        raise NVDQueryNormalizationError(f"Normalized query collision: {exc}") from exc
    return {
        "status": "verified_existing" if existed else "normalized",
        "query_id": query_id,
        "record_count": normalized["record_count"],
        "pages_reconciled": len(normalized["source_pages"]),
        "output_sha256": hashlib.sha256(content).hexdigest(),
        "output_path": str(output),
        "point_in_time_consistency_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline normalized NVD completed-query replay")
    parser.add_argument("--query-id", required=True)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args(argv)
    try:
        result = normalize_archived_nvd_query(args.data_dir, query_id=args.query_id)
    except (NVDQueryNormalizationError, OSError) as exc:
        print(f"NVD query normalization failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
