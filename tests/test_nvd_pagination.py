"""EA-03A2B deterministic offline coverage; no real NVD HTTP requests."""

import hashlib
import json
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from patchline.ingest.nvd_acquire import NVDAcquisitionError, build_nvd_request
from patchline.ingest.nvd_pagination import acquire_nvd_query, main

IDS = (
    "CVE-2026-10001",
    "CVE-2026-10002",
    "CVE-2026-10003",
    "CVE-2026-10004",
    "CVE-2026-10005",
)


def page(index: int, ids: tuple[str, ...], *, total: int = 5, size: int = 2) -> bytes:
    return json.dumps(
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": f"2026-11-13T12:00:{index:02d}.000",
            "startIndex": index,
            "resultsPerPage": size,
            "totalResults": total,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": identifier,
                        "published": "2026-11-01T00:00:00.000",
                        "lastModified": "2026-11-12T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "Synthetic example"}],
                    }
                }
                for identifier in ids
            ],
        },
        sort_keys=True,
    ).encode()


def query() -> dict:
    return build_nvd_request(
        last_mod_start="2026-11-12T00:00:00Z",
        last_mod_end="2026-11-13T00:00:00Z",
        results_per_page=2,
    )


def scripted(pages: dict[int, bytes], seen: list | None = None):
    def fetch(url: str, key: str | None, timeout: int) -> bytes:
        index = int(parse_qs(urlsplit(url).query)["startIndex"][0])
        if seen is not None:
            seen.append((index, key, timeout))
        return pages[index]

    return fetch


def test_complete_three_pages_is_reported_total_reconciled(tmp_path: Path) -> None:
    calls = []
    sleeps = []
    result = acquire_nvd_query(
        tmp_path,
        request=query(),
        max_pages=3,
        fetch=scripted(
            {0: page(0, IDS[:2]), 2: page(2, IDS[2:4]), 4: page(4, IDS[4:])}, calls
        ),
        sleep=sleeps.append,
        now=lambda: datetime(2026, 11, 13, 13, tzinfo=UTC),
    )
    assert result["status"] == "acquired"
    assert result["unique_cve_count"] == 5
    assert result["pagination_reconciled"] is True
    assert result["point_in_time_consistency_verified"] is False
    assert calls == [(0, None, 30), (2, None, 30), (4, None, 30)]
    assert sleeps == [6.5, 6.5]
    manifest = json.loads(Path(result["query_manifest"]).read_text())
    assert manifest["pages_retrieved"] == 3
    assert [p["start_index"] for p in manifest["pages"]] == [0, 2, 4]
    assert [p["row_count"] for p in manifest["pages"]] == [2, 2, 1]
    assert manifest["reported_total_results"] == 5
    assert manifest["global_nvd_completeness_attested"] is False
    assert manifest["point_in_time_consistency_verified"] is False
    for entry in manifest["pages"]:
        raw = tmp_path / entry["raw_page_relative_path"]
        assert raw.exists()
        assert hashlib.sha256(raw.read_bytes()).hexdigest() == entry["sha256"]


def test_exact_multiple_has_no_extra_request(tmp_path: Path) -> None:
    calls = []
    result = acquire_nvd_query(
        tmp_path,
        request=query(),
        fetch=scripted({0: page(0, IDS[:2], total=4), 2: page(2, IDS[2:4], total=4)}, calls),
        sleep=lambda _: None,
    )
    assert result["pages_retrieved"] == 2
    assert [c[0] for c in calls] == [0, 2]


def test_single_page_is_valid_query_level_result(tmp_path: Path) -> None:
    calls = []
    result = acquire_nvd_query(
        tmp_path,
        request=query(),
        fetch=scripted({0: page(0, IDS[:1], total=1)}, calls),
    )
    assert result["pages_retrieved"] == 1
    assert len(calls) == 1


def test_cve_query_identity_is_enforced(tmp_path: Path) -> None:
    request = build_nvd_request(cve_id=IDS[0], results_per_page=1)
    with pytest.raises(NVDAcquisitionError, match="unexpected record"):
        acquire_nvd_query(
            tmp_path,
            request=request,
            fetch=lambda *_: page(0, IDS[1:2], total=1, size=1),
        )
    assert not (tmp_path / "raw").exists()


@pytest.mark.parametrize(
    "pages,error",
    [
        ({0: page(0, IDS[:2]), 2: page(2, IDS[2:4], total=6)}, "totalResults changed"),
        ({0: page(0, IDS[:2]), 2: page(0, IDS[2:4])}, "startIndex"),
        ({0: page(0, IDS[:2]), 2: page(2, IDS[1:3])}, "Duplicate CVE"),
        ({0: page(0, IDS[:2]), 2: page(2, IDS[2:3])}, "gap, partial"),
        ({0: page(0, IDS[:2]), 2: page(2, IDS[2:4], size=3)}, "page size"),
        ({0: page(0, IDS[:2]), 2: b"not json"}, "Invalid NVD page"),
        ({0: page(0, IDS[:2]), 2: page(2, (), total=5)}, "Invalid NVD page"),
    ],
)
def test_inconsistent_pages_rejected_without_query_marker(
    tmp_path: Path, pages: dict[int, bytes], error: str
) -> None:
    with pytest.raises(NVDAcquisitionError, match=error):
        acquire_nvd_query(tmp_path, request=query(), fetch=scripted(pages), sleep=lambda _: None)
    assert not (tmp_path / "raw" / "nvd-queries").exists()
    assert not (tmp_path / "raw" / "nvd").exists()


def test_max_pages_rejected_before_archival(tmp_path: Path) -> None:
    with pytest.raises(NVDAcquisitionError, match="max_pages bound"):
        acquire_nvd_query(
            tmp_path,
            request=query(),
            max_pages=2,
            fetch=scripted({0: page(0, IDS[:2])}),
        )
    assert not (tmp_path / "raw").exists()


def test_api_key_never_stored(tmp_path: Path) -> None:
    calls = []
    pauses = []
    result = acquire_nvd_query(
        tmp_path,
        request=query(),
        api_key="DO-NOT-PUBLISH-THIS",
        max_pages=1,
        fetch=scripted({0: page(0, IDS[:2], total=2)}, calls),
        sleep=pauses.append,
    )
    assert calls == [(0, "DO-NOT-PUBLISH-THIS", 30)]
    assert pauses == []
    assert "DO-NOT-PUBLISH-THIS" not in Path(result["query_manifest"]).read_text()


def test_same_query_bytes_reuse_immutable_manifest(tmp_path: Path) -> None:
    kwargs = {
        "request": query(),
        "max_pages": 1,
        "fetch": scripted({0: page(0, IDS[:2], total=2)}),
    }
    first = acquire_nvd_query(
        tmp_path, **kwargs, now=lambda: datetime(2026, 11, 13, 12, tzinfo=UTC)
    )
    second = acquire_nvd_query(
        tmp_path, **kwargs, now=lambda: datetime(2026, 11, 14, 12, tzinfo=UTC)
    )
    assert second["status"] == "skipped_existing"
    assert first["query_id"] == second["query_id"]
    manifest = json.loads(Path(first["query_manifest"]).read_text())
    assert manifest["acquired_at_utc"] == "2026-11-13T12:00:00.000Z"


def test_existing_query_manifest_tampering_fails(tmp_path: Path) -> None:
    kwargs = {
        "request": query(),
        "fetch": scripted({0: page(0, IDS[:2], total=2)}),
    }
    first = acquire_nvd_query(tmp_path, **kwargs)
    path = Path(first["query_manifest"])
    manifest = json.loads(path.read_text())
    manifest["unique_cve_count"] = 999
    path.write_text(json.dumps(manifest))
    with pytest.raises(NVDAcquisitionError, match="manifest differs"):
        acquire_nvd_query(tmp_path, **kwargs)


def test_raw_archive_tampering_fails(tmp_path: Path) -> None:
    content = page(0, IDS[:2], total=2)
    kwargs = {"request": query(), "fetch": lambda *_: content}
    result = acquire_nvd_query(tmp_path, **kwargs)
    raw = tmp_path / "raw" / "nvd" / hashlib.sha256(content).hexdigest() / "page.json"
    raw.write_bytes(b"tampered")
    with pytest.raises(NVDAcquisitionError, match="archive"):
        acquire_nvd_query(tmp_path, **kwargs)
    assert Path(result["query_manifest"]).exists()


def test_retry_429_and_interpage_spacing(tmp_path: Path) -> None:
    seen = []
    sleeps = []

    def fetch(url, key, timeout):
        index = int(parse_qs(urlsplit(url).query)["startIndex"][0])
        seen.append(index)
        if len(seen) == 1:
            raise urllib.error.HTTPError(url, 429, "retry", {}, None)
        return page(index, IDS[index : index + 2], total=4)

    result = acquire_nvd_query(
        tmp_path, request=query(), fetch=fetch, sleep=sleeps.append
    )
    assert result["pages_retrieved"] == 2
    assert seen == [0, 0, 2]
    assert sleeps == [6.5, 6.5]


@pytest.mark.parametrize("invalid", [0, 21, True, "2", -1])
def test_invalid_page_limit_cannot_contact_network(tmp_path: Path, invalid) -> None:
    with pytest.raises(NVDAcquisitionError, match="max_pages"):
        acquire_nvd_query(
            tmp_path,
            request=query(),
            max_pages=invalid,
            fetch=lambda *_: pytest.fail("Network called"),
        )


def test_tampered_request_cannot_contact_network(tmp_path: Path) -> None:
    request = query()
    request["url"] = "https://invalid.example/"
    with pytest.raises(NVDAcquisitionError, match="approved first-page plan"):
        acquire_nvd_query(
            tmp_path, request=request, fetch=lambda *_: pytest.fail("Network called")
        )


def test_missing_timezone_clock_rejected_before_network(tmp_path: Path) -> None:
    with pytest.raises(NVDAcquisitionError, match="timezone-aware"):
        acquire_nvd_query(
            tmp_path,
            request=query(),
            now=lambda: datetime(2026, 11, 13),
            fetch=lambda *_: pytest.fail("Network called"),
        )


def test_cli_denies_network_by_default(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "--last-mod-start",
                "2026-11-12T00:00:00Z",
                "--last-mod-end",
                "2026-11-13T00:00:00Z",
                "--data-dir",
                str(tmp_path),
            ]
        )
        == 1
    )
    assert "--allow-network" in capsys.readouterr().err
    assert not (tmp_path / "raw").exists()
