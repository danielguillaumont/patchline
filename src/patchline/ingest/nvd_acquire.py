"""EA-03A2A: deliberately bounded, opt-in acquisition of ONE NVD API page.

No background sync, full-dataset download, or query-completeness certification.
The existing EA-03A1 page validator is the authoritative payload boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from patchline.ingest.kev import KEVIngestionError, _atomic_write_new
from patchline.ingest.nvd import (
    CVE_RE,
    MAX_PAGE_BYTES,
    NVD_CVE_API,
    NVDIngestionError,
    archive_nvd_page,
    validate_nvd_page,
)

ACQUISITION_VERSION = "patchline.nvd-acquisition.v1"
MAX_RESULTS_PER_PAGE = 2_000
DEFAULT_RESULTS_PER_PAGE = 100
MAX_WINDOW_DAYS = 120
DEFAULT_TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 3
# These deliberate minimum intervals are more conservative than the published
# NVD request limits. All calls in this slice are serial, including retries.
NO_KEY_MIN_INTERVAL_SECONDS = 6.5
KEY_MIN_INTERVAL_SECONDS = 0.7
RETRYABLE_HTTP_CODES = frozenset({429, 500, 502, 503, 504})


class NVDAcquisitionError(ValueError):
    """A request, response, or acquisition record failed closed."""


def _utc_timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise NVDAcquisitionError(f"{field} must be an ISO-8601 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NVDAcquisitionError(f"Invalid {field} ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise NVDAcquisitionError(f"{field} needs an explicit UTC offset")
    return parsed.astimezone(UTC)


def _format_utc(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_nvd_request(
    *,
    cve_id: str | None = None,
    last_mod_start: str | None = None,
    last_mod_end: str | None = None,
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
) -> dict[str, Any]:
    """Define an auditable single-page NVD API 2.0 query, without sending it."""
    if type(results_per_page) is not int or not 1 <= results_per_page <= MAX_RESULTS_PER_PAGE:
        raise NVDAcquisitionError("resultsPerPage must be an integer from 1 to 2000")
    if (cve_id is None) == (last_mod_start is None and last_mod_end is None):
        raise NVDAcquisitionError("Choose exactly one query mode: CVE ID or last-modified window")
    parameters: dict[str, str] = {
        "resultsPerPage": str(results_per_page),
        "startIndex": "0",
    }
    if cve_id is not None:
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
            raise NVDAcquisitionError("Invalid CVE identifier")
        if last_mod_start is not None or last_mod_end is not None:
            raise NVDAcquisitionError("Cannot combine CVE ID and time-window filters")
        parameters["cveId"] = cve_id
        query_mode = "cve_id"
    else:
        if last_mod_start is None or last_mod_end is None:
            raise NVDAcquisitionError("Both last-modified timestamps are required")
        start = _utc_timestamp(last_mod_start, "lastModStartDate")
        end = _utc_timestamp(last_mod_end, "lastModEndDate")
        if end <= start or end - start > timedelta(days=MAX_WINDOW_DAYS):
            raise NVDAcquisitionError("NVD time window must be positive and at most 120 days")
        parameters["lastModStartDate"] = _format_utc(start)
        parameters["lastModEndDate"] = _format_utc(end)
        query_mode = "last_modified_window"
    url = f"{NVD_CVE_API}?{urllib.parse.urlencode(sorted(parameters.items()))}"
    return {"endpoint": NVD_CVE_API, "query_mode": query_mode, "parameters": parameters, "url": url}


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise NVDAcquisitionError("NVD API redirect rejected")


def _fetch_https(url: str, api_key: str | None, *, timeout: int) -> bytes:
    """Fetch one byte-bounded official NVD response; never forward a key to redirects."""
    if not url.startswith(NVD_CVE_API + "?"):
        raise NVDAcquisitionError("Refusing non-NVD endpoint")
    headers = {"Accept": "application/json", "User-Agent": "ExploitAtlas/EA03A2A (research client)"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_RejectRedirect)
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(MAX_PAGE_BYTES + 1)
    if len(raw) > MAX_PAGE_BYTES:
        raise NVDAcquisitionError("NVD response exceeds 20 MiB single-page limit")
    return raw


def _fetch_with_retries(
    url: str,
    *,
    api_key: str | None,
    timeout: int,
    fetch: Callable[[str, str | None, int], bytes],
    sleep: Callable[[float], None],
) -> bytes:
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = fetch(url, api_key, timeout)
            if not isinstance(response, bytes):
                raise NVDAcquisitionError("Transport must return raw response bytes")
            return response
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP_CODES:
                raise NVDAcquisitionError(f"NVD HTTP {exc.code}; no retry") from exc
            if attempt == MAX_ATTEMPTS - 1:
                raise NVDAcquisitionError(f"NVD HTTP {exc.code}; retry budget exhausted") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if attempt == MAX_ATTEMPTS - 1:
                raise NVDAcquisitionError("NVD transport retry budget exhausted") from exc
        # Rate spacing applies to retries as well as ordinary requests.
        minimum = KEY_MIN_INTERVAL_SECONDS if api_key else NO_KEY_MIN_INTERVAL_SECONDS
        sleep(max(minimum, 2 ** attempt))
    raise NVDAcquisitionError("NVD acquisition failed")


def _json_bytes(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def acquire_nvd_page(
    data_dir: Path,
    *,
    request: dict[str, Any],
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    fetch: Callable[[str, str | None, int], bytes] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Acquire, validate and archive one page with an immutable request record.

    Explicitly does not prove that the NVD query had no subsequent pages.
    """
    if not isinstance(request, dict) or not isinstance(request.get("url"), str):
        raise NVDAcquisitionError("Invalid request plan")
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise NVDAcquisitionError("HTTP timeout must be 1 to 120 seconds")
    expected = build_nvd_request(
        cve_id=request.get("parameters", {}).get("cveId"),
        last_mod_start=request.get("parameters", {}).get("lastModStartDate"),
        last_mod_end=request.get("parameters", {}).get("lastModEndDate"),
        results_per_page=int(request.get("parameters", {}).get("resultsPerPage", -1)),
    )
    if request != expected:
        raise NVDAcquisitionError("Request plan differs from allowlisted NVD request")

    def transport(url: str, key: str | None, seconds: int) -> bytes:
        return _fetch_https(url, key, timeout=seconds)

    content = _fetch_with_retries(
        expected["url"],
        api_key=api_key,
        timeout=timeout,
        fetch=fetch or transport,
        sleep=sleep,
    )
    try:
        page = validate_nvd_page(content)
    except NVDIngestionError as exc:
        raise NVDAcquisitionError(f"Untrusted NVD response: {exc}") from exc
    if page["start_index"] != 0 or page["results_per_page"] > int(
        expected["parameters"]["resultsPerPage"]
    ):
        raise NVDAcquisitionError("Response pagination exceeds requested first-page bounds")
    if expected["query_mode"] == "cve_id":
        parsed = json.loads(content)
        ids = [entry["cve"]["id"] for entry in parsed["vulnerabilities"]]
        if ids != [expected["parameters"]["cveId"]]:
            raise NVDAcquisitionError("CVE-ID query returned an unexpected record")

    page_digest = hashlib.sha256(content).hexdigest()
    query_digest = hashlib.sha256(expected["url"].encode("utf-8")).hexdigest()
    acquisition_id = hashlib.sha256((query_digest + ":" + page_digest).encode("ascii")).hexdigest()
    stamp = (now or (lambda: datetime.now(UTC)))()
    if stamp.tzinfo is None:
        raise NVDAcquisitionError("Acquisition clock must be timezone-aware")
    manifest: dict[str, Any] = {
        "format_version": ACQUISITION_VERSION,
        "source": "NIST NVD CVE API 2.0",
        "acquisition_type": "explicit_https_single_page",
        "acquisition_id": acquisition_id,
        "acquired_at_utc": _format_utc(stamp.astimezone(UTC)),
        "query_sha256": query_digest,
        "query_mode": expected["query_mode"],
        "request_url": expected["url"],
        "request_parameters": expected["parameters"],
        "page_sha256": page_digest,
        "page_byte_count": len(content),
        "page_response_timestamp": page["response_timestamp"],
        "page_start_index": page["start_index"],
        "page_row_count": page["row_count"],
        "reported_total_results": page["reported_total_results"],
        "reported_total_fits_first_page": page["row_count"] == page["reported_total_results"],
        "completeness_attested": False,
        "point_in_time_consistency_verified": False,
        "scope": "one_NVD_API_response_page_only",
        "raw_page_relative_path": f"raw/nvd/{page_digest}/page.json",
    }
    # Both source and request metadata are append-only. The EA03A1 archive still
    # denotes offline-supplied bytes; this separate record documents HTTP origin.
    destination = data_dir / "raw" / "nvd-acquisitions" / acquisition_id / "acquisition.json"
    if destination.exists():
        try:
            original = json.loads(destination.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise NVDAcquisitionError("Existing acquisition record is corrupt") from exc
        if not isinstance(original, dict) or set(original) != set(manifest):
            raise NVDAcquisitionError("Existing acquisition record inventory differs")
        for key in manifest:
            if key != "acquired_at_utc" and original[key] != manifest[key]:
                raise NVDAcquisitionError(f"Existing acquisition record mismatch: {key}")
        _utc_timestamp(original["acquired_at_utc"], "archived acquisition timestamp")
        manifest = original
        status = "skipped_existing"
    else:
        status = "acquired"

    # Archive the exact downloaded bytes using the previously validated EA03A1
    # path, ensuring any pre-existing raw payload is checked before acceptance.
    try:
        page_archive = archive_nvd_page(data_dir, page_bytes=content)
    except NVDIngestionError as exc:
        raise NVDAcquisitionError(str(exc)) from exc
    if page_archive["page_sha256"] != page_digest:
        raise NVDAcquisitionError("Page archive digest mismatch")
    if status == "acquired":
        try:
            _atomic_write_new(destination, _json_bytes(manifest))
        except KEVIngestionError as exc:
            raise NVDAcquisitionError(str(exc)) from exc
    return {
        "status": status,
        "acquisition_id": acquisition_id,
        "acquisition_manifest": str(destination),
        "raw_page_sha256": page_digest,
        "page_rows": page["row_count"],
        "reported_total_results": page["reported_total_results"],
        "single_page_only": True,
        "completeness_attested": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit, bounded first-page NVD acquisition")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve-id")
    group.add_argument("--last-mod-start")
    parser.add_argument("--last-mod-end")
    parser.add_argument("--results-per-page", type=int, default=DEFAULT_RESULTS_PER_PAGE)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--allow-network", action="store_true", help="Required explicit consent")
    args = parser.parse_args(argv)
    try:
        request = build_nvd_request(
            cve_id=args.cve_id,
            last_mod_start=args.last_mod_start,
            last_mod_end=args.last_mod_end,
            results_per_page=args.results_per_page,
        )
        if not args.allow_network:
            raise NVDAcquisitionError("Network acquisition is disabled; pass --allow-network")
        record = acquire_nvd_page(
            args.data_dir, request=request, api_key=os.environ.get("NVD_API_KEY") or None
        )
    except (NVDAcquisitionError, OSError) as exc:
        print(f"NVD acquisition failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
