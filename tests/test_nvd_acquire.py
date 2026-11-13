"""EA-03A2A: all NVD acquisition tests are offline and transport-injected."""

import hashlib
import json
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from patchline.ingest.nvd_acquire import (
    NVDAcquisitionError,
    _fetch_with_retries,
    acquire_nvd_page,
    build_nvd_request,
    main,
)


def make_page(
    *,
    start_index: int = 0,
    results_per_page: int = 2,
    total_results: int = 2,
    identifiers: tuple[str, ...] = ("CVE-2026-12345", "CVE-2026-54321"),
) -> bytes:
    record = {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-11-13T12:00:00.000",
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
        "totalResults": total_results,
        "vulnerabilities": [
            {
                "cve": {
                    "id": identifier,
                    "published": "2026-11-01T00:00:00.000",
                    "lastModified": "2026-11-12T12:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Invented data"}],
                }
            }
            for identifier in identifiers
        ],
    }
    return json.dumps(record).encode("utf-8")


def plan_for_two() -> dict:
    return build_nvd_request(
        last_mod_start="2026-11-12T00:00:00Z",
        last_mod_end="2026-11-13T00:00:00Z",
        results_per_page=2,
    )


def test_cve_request_is_bounded_and_official() -> None:
    request = build_nvd_request(cve_id="CVE-2026-12345")
    parts = urlsplit(request["url"])
    assert parts.scheme == "https"
    assert parts.hostname == "services.nvd.nist.gov"
    assert parts.path == "/rest/json/cves/2.0"
    assert parse_qs(parts.query) == {
        "cveId": ["CVE-2026-12345"],
        "resultsPerPage": ["100"],
        "startIndex": ["0"],
    }


def test_window_offsets_convert_to_explicit_utc() -> None:
    request = build_nvd_request(
        last_mod_start="2026-11-12T04:00:00+04:00",
        last_mod_end="2026-11-13T00:00:00+00:00",
    )
    assert request["parameters"]["lastModStartDate"] == "2026-11-12T00:00:00.000Z"
    assert request["parameters"]["lastModEndDate"] == "2026-11-13T00:00:00.000Z"


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"cve_id": "bad"},
        {"cve_id": "CVE-2026-12345", "last_mod_start": "2026-01-01T00:00:00Z"},
        {"last_mod_start": "2026-01-01T00:00:00Z"},
        {"last_mod_end": "2026-01-01T00:00:00Z"},
        {"last_mod_start": "2026-01-01", "last_mod_end": "2026-01-02T00:00:00Z"},
        {"last_mod_start": "2026-01-01T00:00:00Z", "last_mod_end": "2026-01-01T00:00:00Z"},
        {"last_mod_start": "2026-01-02T00:00:00Z", "last_mod_end": "2026-01-01T00:00:00Z"},
        {"last_mod_start": "2026-01-01T00:00:00Z", "last_mod_end": "2026-05-02T00:00:00Z"},
        {"cve_id": "CVE-2026-12345", "results_per_page": 0},
        {"cve_id": "CVE-2026-12345", "results_per_page": 2001},
        {"cve_id": "CVE-2026-12345", "results_per_page": True},
    ],
)
def test_bad_request_plan_fails_closed(kwargs: dict) -> None:
    with pytest.raises(NVDAcquisitionError):
        build_nvd_request(**kwargs)


def test_acquisition_archives_bytes_and_request_without_secret(tmp_path: Path) -> None:
    seen = []
    content = make_page()
    api_key = "SECRET-DO-NOT-PERSIST"

    def fetch(url: str, key: str | None, timeout: int) -> bytes:
        seen.append((url, key, timeout))
        return content

    result = acquire_nvd_page(
        tmp_path,
        request=plan_for_two(),
        api_key=api_key,
        fetch=fetch,
        sleep=lambda _: pytest.fail("Unexpected retry"),
        now=lambda: datetime(2026, 11, 13, 12, tzinfo=UTC),
    )
    assert result["status"] == "acquired"
    assert result["single_page_only"] is True
    assert result["completeness_attested"] is False
    assert seen[0][1:] == (api_key, 30)
    acquisition_path = Path(result["acquisition_manifest"])
    saved = json.loads(acquisition_path.read_text(encoding="utf-8"))
    assert saved["reported_total_fits_first_page"] is True
    assert saved["point_in_time_consistency_verified"] is False
    assert api_key not in acquisition_path.read_text(encoding="utf-8")
    digest = hashlib.sha256(content).hexdigest()
    assert (tmp_path / "raw" / "nvd" / digest / "page.json").read_bytes() == content
    assert saved["raw_page_relative_path"] == f"raw/nvd/{digest}/page.json"


def test_partial_page_explicitly_not_complete(tmp_path: Path) -> None:
    result = acquire_nvd_page(
        tmp_path,
        request=plan_for_two(),
        fetch=lambda *_: make_page(total_results=3),
    )
    saved = json.loads(Path(result["acquisition_manifest"]).read_text())
    assert saved["reported_total_fits_first_page"] is False
    assert saved["completeness_attested"] is False


def test_cve_id_response_must_match_query(tmp_path: Path) -> None:
    request = build_nvd_request(cve_id="CVE-2026-12345", results_per_page=1)
    with pytest.raises(NVDAcquisitionError, match="unexpected record"):
        acquire_nvd_page(
            tmp_path,
            request=request,
            fetch=lambda *_: make_page(
                results_per_page=1, total_results=1, identifiers=("CVE-2026-54321",)
            ),
        )
    assert not (tmp_path / "raw").exists()


@pytest.mark.parametrize(
    "content",
    [
        make_page(start_index=1, total_results=3),
        make_page(results_per_page=5),
        b"not json",
        b"[]",
        b"",
    ],
)
def test_bad_page_metadata_rejected_before_archiving(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(NVDAcquisitionError):
        acquire_nvd_page(tmp_path, request=plan_for_two(), fetch=lambda *_: content)
    assert not (tmp_path / "raw").exists()


def test_request_plan_tampering_fails_without_network(tmp_path: Path) -> None:
    request = plan_for_two()
    request["url"] = "https://evil.example/download?apiKey=oops"
    with pytest.raises(NVDAcquisitionError, match="allowlisted"):
        acquire_nvd_page(tmp_path, request=request, fetch=lambda *_: pytest.fail("Network used"))


def test_idempotent_acquisition_retains_original_timestamp(tmp_path: Path) -> None:
    request = plan_for_two()
    first = acquire_nvd_page(
        tmp_path,
        request=request,
        fetch=lambda *_: make_page(),
        now=lambda: datetime(2026, 11, 13, 12, tzinfo=UTC),
    )
    second = acquire_nvd_page(
        tmp_path,
        request=request,
        fetch=lambda *_: make_page(),
        now=lambda: datetime(2026, 11, 14, 12, tzinfo=UTC),
    )
    assert second["status"] == "skipped_existing"
    assert first["acquisition_id"] == second["acquisition_id"]
    saved = json.loads(Path(second["acquisition_manifest"]).read_text())
    assert saved["acquired_at_utc"] == "2026-11-13T12:00:00.000Z"


def test_tampered_existing_acquisition_fails(tmp_path: Path) -> None:
    request = plan_for_two()
    first = acquire_nvd_page(tmp_path, request=request, fetch=lambda *_: make_page())
    location = Path(first["acquisition_manifest"])
    record = json.loads(location.read_text(encoding="utf-8"))
    record["page_row_count"] = 900
    location.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(NVDAcquisitionError, match="record mismatch"):
        acquire_nvd_page(tmp_path, request=request, fetch=lambda *_: make_page())


def test_429_is_retried_with_rate_spacing() -> None:
    attempts = []
    pauses = []

    def fetch(url: str, key: str | None, timeout: int) -> bytes:
        attempts.append(url)
        if len(attempts) == 1:
            raise urllib.error.HTTPError(url, 429, "Throttled", {}, None)
        return b"ok"

    result = _fetch_with_retries(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=x",
        api_key=None,
        timeout=30,
        fetch=fetch,
        sleep=pauses.append,
    )
    assert result == b"ok"
    assert len(attempts) == 2
    assert pauses == [6.5]


def test_key_rate_spacing_is_used_on_retry() -> None:
    attempts = []
    pauses = []

    def fetch(url: str, key: str | None, timeout: int) -> bytes:
        attempts.append(key)
        if len(attempts) < 3:
            raise urllib.error.HTTPError(url, 503, "Unavailable", {}, None)
        return b"ok"

    result = _fetch_with_retries(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=x",
        api_key="secret",
        timeout=30,
        fetch=fetch,
        sleep=pauses.append,
    )
    assert result == b"ok"
    assert attempts == ["secret"] * 3
    assert pauses == [1, 2]


def test_403_does_not_retry() -> None:
    pauses = []

    def fetch(url: str, key: str | None, timeout: int) -> bytes:
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    with pytest.raises(NVDAcquisitionError, match="403"):
        _fetch_with_retries("url", api_key=None, timeout=30, fetch=fetch, sleep=pauses.append)
    assert pauses == []


def test_503_budget_is_finite() -> None:
    pauses = []
    attempts = []

    def fetch(url: str, key: str | None, timeout: int) -> bytes:
        attempts.append(url)
        raise urllib.error.HTTPError(url, 503, "unavailable", {}, None)

    with pytest.raises(NVDAcquisitionError, match="exhausted"):
        _fetch_with_retries("url", api_key=None, timeout=30, fetch=fetch, sleep=pauses.append)
    assert len(attempts) == 3
    assert pauses == [6.5, 6.5]


def test_cli_never_uses_network_without_explicit_switch(tmp_path: Path, capsys) -> None:
    assert main(["--cve-id", "CVE-2026-12345", "--data-dir", str(tmp_path)]) == 1
    assert "--allow-network" in capsys.readouterr().err
    assert not (tmp_path / "raw").exists()


def test_missing_end_date_rejected(capsys) -> None:
    assert main(["--last-mod-start", "2026-11-12T00:00:00Z", "--allow-network"]) == 1
    assert "required" in capsys.readouterr().err
