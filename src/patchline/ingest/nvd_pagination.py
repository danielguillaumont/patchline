"""EA-03A2B: bounded, auditable NVD API pagination for an explicit query.

A reconciled query is NOT an atomic or point-in-time snapshot of the NVD.
No DB ingest, background sync, or public-site publication occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchline.ingest.kev import KEVIngestionError, _atomic_write_new
from patchline.ingest.nvd import NVDIngestionError, archive_nvd_page, validate_nvd_page
from patchline.ingest.nvd_acquire import (
    DEFAULT_RESULTS_PER_PAGE,
    DEFAULT_TIMEOUT_SECONDS,
    KEY_MIN_INTERVAL_SECONDS,
    NO_KEY_MIN_INTERVAL_SECONDS,
    NVDAcquisitionError,
    _fetch_https,
    _fetch_with_retries,
    _format_utc,
    _utc_timestamp,
    build_nvd_request,
)

QUERY_FORMAT_VERSION = "patchline.nvd-query-pagination.v1"
MAX_QUERY_PAGES = 20
DEFAULT_MAX_PAGES = 10
MAX_QUERY_BYTES = 64 * 1024 * 1024


def _validated_request(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict) or not isinstance(request.get("parameters"), dict):
        raise NVDAcquisitionError("Invalid NVD query request")
    params = request["parameters"]
    per_page = params.get("resultsPerPage")
    if not isinstance(per_page, str) or not per_page.isascii() or not per_page.isdecimal():
        raise NVDAcquisitionError("Invalid requested page size")
    try:
        rebuilt = build_nvd_request(
            cve_id=params.get("cveId"),
            last_mod_start=params.get("lastModStartDate"),
            last_mod_end=params.get("lastModEndDate"),
            results_per_page=int(per_page),
        )
    except (TypeError, ValueError) as exc:
        raise NVDAcquisitionError("Invalid allowlisted NVD query") from exc
    if request != rebuilt:
        raise NVDAcquisitionError("NVD query differs from the approved first-page plan")
    return rebuilt


def _page_url(request: dict[str, Any], index: int) -> str:
    params = {**request["parameters"], "startIndex": str(index)}
    return f"{request['endpoint']}?{urllib.parse.urlencode(sorted(params.items()))}"


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def acquire_nvd_query(
    data_dir: Path,
    *,
    request: dict[str, Any],
    api_key: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    fetch: Callable[[str, str | None, int], bytes] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Fetch every page up to hard bounds; archive only after full reconciliation.

    A success proves pagination agrees with NVD's *reported* total across
    this retrieval. It does NOT prove the API was stable between page fetches.
    """
    approved = _validated_request(request)
    if type(max_pages) is not int or not 1 <= max_pages <= MAX_QUERY_PAGES:
        raise NVDAcquisitionError("max_pages must be an integer from 1 to 20")
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise NVDAcquisitionError("HTTP timeout must be 1 to 120 seconds")
    stamp = (now or (lambda: datetime.now(UTC)))()
    if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp.utcoffset() is None:
        raise NVDAcquisitionError("Acquisition clock must be timezone-aware")
    per_page = int(approved["parameters"]["resultsPerPage"])
    query_sha = hashlib.sha256(approved["url"].encode("utf-8")).hexdigest()
    records: list[dict[str, Any]] = []
    payloads: list[bytes] = []
    seen: set[str] = set()
    total: int | None = None
    total_bytes = 0
    processed = 0

    def transport(url: str, key: str | None, seconds: int) -> bytes:
        return _fetch_https(url, key, timeout=seconds)

    for page_number in range(max_pages):
        if total is not None and processed >= total:
            break
        if page_number:
            # Extra spacing between successful requests; internal retry pauses
            # are handled separately by the bounded transport.
            sleep(KEY_MIN_INTERVAL_SECONDS if api_key else NO_KEY_MIN_INTERVAL_SECONDS)
        url = _page_url(approved, processed)
        content = _fetch_with_retries(
            url, api_key=api_key, timeout=timeout, fetch=fetch or transport, sleep=sleep
        )
        total_bytes += len(content)
        if total_bytes > MAX_QUERY_BYTES:
            raise NVDAcquisitionError("NVD query exceeds the 64 MiB cumulative size bound")
        try:
            metadata = validate_nvd_page(content)
        except NVDIngestionError as exc:
            raise NVDAcquisitionError(f"Invalid NVD page {page_number}: {exc}") from exc
        if metadata["start_index"] != processed:
            raise NVDAcquisitionError("NVD page startIndex does not match requested offset")
        if metadata["results_per_page"] != per_page:
            raise NVDAcquisitionError("NVD page size changed during query")
        if total is None:
            total = metadata["reported_total_results"]
            if total > max_pages * per_page:
                raise NVDAcquisitionError("Reported NVD total exceeds explicit max_pages bound")
        elif metadata["reported_total_results"] != total:
            raise NVDAcquisitionError("NVD totalResults changed between pages")
        assert total is not None
        remaining = total - processed
        if remaining <= 0 or metadata["row_count"] != min(per_page, remaining):
            raise NVDAcquisitionError("NVD page contains a gap, partial page, or unexpected count")
        try:
            parsed = json.loads(content)
            identifiers = [row["cve"]["id"] for row in parsed["vulnerabilities"]]
        except (ValueError, TypeError, KeyError) as exc:
            raise NVDAcquisitionError("NVD page identifiers could not be read") from exc
        for cve_id in identifiers:
            if cve_id in seen:
                raise NVDAcquisitionError(f"Duplicate CVE across NVD pages: {cve_id}")
            seen.add(cve_id)
        if approved["query_mode"] == "cve_id" and identifiers != [
            approved["parameters"]["cveId"]
        ]:
            raise NVDAcquisitionError("CVE-ID query returned unexpected record(s)")
        digest = hashlib.sha256(content).hexdigest()
        records.append(
            {
                "start_index": processed,
                "results_per_page": per_page,
                "row_count": metadata["row_count"],
                "response_timestamp": metadata["response_timestamp"],
                "request_url": url,
                "sha256": digest,
                "byte_count": len(content),
                "raw_page_relative_path": f"raw/nvd/{digest}/page.json",
            }
        )
        payloads.append(content)
        processed += metadata["row_count"]

    if total is None or processed != total or len(seen) != total:
        raise NVDAcquisitionError("NVD query not complete within bounded pagination")

    content_id = hashlib.sha256(
        _json_bytes({"query_sha256": query_sha, "pages": [item["sha256"] for item in records]})
    ).hexdigest()
    manifest = {
        "format_version": QUERY_FORMAT_VERSION,
        "source": "NIST NVD CVE API 2.0",
        "acquisition_type": "explicit_bounded_https_paginated_query",
        "query_id": content_id,
        "acquired_at_utc": _format_utc(stamp.astimezone(UTC)),
        "query_sha256": query_sha,
        "query_mode": approved["query_mode"],
        "first_page_request_url": approved["url"],
        "request_parameters": approved["parameters"],
        "requested_max_pages": max_pages,
        "pages_retrieved": len(records),
        "pages": records,
        "reported_total_results": total,
        "unique_cve_count": len(seen),
        "total_response_bytes": total_bytes,
        "pagination_reconciled": True,
        "scope": "query_pagination_vs_reported_total_only",
        "point_in_time_consistency_verified": False,
        "global_nvd_completeness_attested": False,
        "zero_result_queries_supported": False,
    }
    manifest_path = data_dir / "raw" / "nvd-queries" / content_id / "manifest.json"

    # All remote pages have now passed validation; archive immutable originals
    # first, and publish the query-level completion marker only at the end.
    for content, item in zip(payloads, records, strict=True):
        try:
            archived = archive_nvd_page(data_dir, page_bytes=content)
        except NVDIngestionError as exc:
            raise NVDAcquisitionError(f"NVD raw page archive failed: {exc}") from exc
        if archived["page_sha256"] != item["sha256"]:
            raise NVDAcquisitionError("NVD archived page digest mismatch")

    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise NVDAcquisitionError("Existing NVD query manifest is corrupt") from exc
        if not isinstance(existing, dict) or set(existing) != set(manifest):
            raise NVDAcquisitionError("Existing NVD query manifest keys mismatch")
        for key in manifest:
            if key != "acquired_at_utc" and existing[key] != manifest[key]:
                raise NVDAcquisitionError(f"Existing NVD query manifest differs: {key}")
        _utc_timestamp(existing["acquired_at_utc"], "existing NVD query acquisition timestamp")
        status = "skipped_existing"
    else:
        try:
            _atomic_write_new(manifest_path, _json_bytes(manifest))
        except KEVIngestionError as exc:
            raise NVDAcquisitionError(str(exc)) from exc
        status = "acquired"
    return {
        "status": status,
        "query_id": content_id,
        "query_manifest": str(manifest_path),
        "pages_retrieved": len(records),
        "unique_cve_count": len(seen),
        "reported_total_results": total,
        "pagination_reconciled": True,
        "point_in_time_consistency_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded NVD multi-page query acquisition")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve-id")
    group.add_argument("--last-mod-start")
    parser.add_argument("--last-mod-end")
    parser.add_argument("--results-per-page", type=int, default=DEFAULT_RESULTS_PER_PAGE)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--allow-network", action="store_true")
    args = parser.parse_args(argv)
    try:
        request = build_nvd_request(
            cve_id=args.cve_id,
            last_mod_start=args.last_mod_start,
            last_mod_end=args.last_mod_end,
            results_per_page=args.results_per_page,
        )
        if not args.allow_network:
            raise NVDAcquisitionError("Network disabled; pass --allow-network explicitly")
        result = acquire_nvd_query(
            args.data_dir,
            request=request,
            api_key=os.environ.get("NVD_API_KEY") or None,
            max_pages=args.max_pages,
        )
    except (NVDAcquisitionError, OSError) as exc:
        print(f"NVD paginated acquisition failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
