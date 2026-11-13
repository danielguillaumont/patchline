"""EA-03A3B offline query normalization with fabricated NVD pages only."""

import hashlib
import json
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from patchline.ingest.nvd import archive_nvd_page, validate_nvd_page
from patchline.ingest.nvd_acquire import build_nvd_request
from patchline.ingest.nvd_pagination import QUERY_FORMAT_VERSION, acquire_nvd_query
from patchline.ingest.nvd_query_normalize import (
    NVDQueryNormalizationError,
    _json_bytes,
    inspect_archived_nvd_query,
    main,
    normalize_archived_nvd_query,
)

IDS = ("CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003", "CVE-2026-10004", "CVE-2026-10005")


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
                        "sourceIdentifier": "synthetic.example",
                        "published": "2026-11-01T00:00:00.000",
                        "lastModified": "2026-11-12T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "Fabricated source record"}],
                        "metrics": {"cvssMetricV31": []},
                    }
                }
                for identifier in ids
            ],
        },
        sort_keys=True,
    ).encode()


def acquire(tmp_path: Path, *, total: int = 5) -> str:
    request = build_nvd_request(
        last_mod_start="2026-11-12T00:00:00Z",
        last_mod_end="2026-11-13T00:00:00Z",
        results_per_page=2,
    )
    records = list(IDS[:total])

    def fake_fetch(url: str, _key: str | None, _timeout: int) -> bytes:
        start = int(parse_qs(urlsplit(url).query)["startIndex"][0])
        return page(start, tuple(records[start : start + 2]), total=total)

    result = acquire_nvd_query(
        tmp_path, request=request, max_pages=3, fetch=fake_fetch, sleep=lambda _: None,
        now=lambda: datetime(2026, 11, 13, 12, tzinfo=UTC),
    )
    return result["query_id"]


def query_path(root: Path, query_id: str) -> Path:
    return root / "raw" / "nvd-queries" / query_id / "manifest.json"


def modify_manifest(root: Path, query_id: str, change) -> None:
    path = query_path(root, query_id)
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_reconciles_three_pages_offline_with_stable_cve_order(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    result = normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert result["status"] == "normalized"
    assert result["record_count"] == 5
    assert result["pages_reconciled"] == 3
    assert result["point_in_time_consistency_verified"] is False
    stored = json.loads(Path(result["output_path"]).read_text())
    assert stored["format_version"] == "patchline.nvd-normalized-query.v1"
    assert stored["query_id"] == query_id
    assert stored["record_count"] == 5
    assert [record["cve_id"] for record in stored["records"]] == list(IDS)
    assert [record["source_page_start_index"] for record in stored["records"]] == [0, 0, 2, 2, 4]
    assert [record["source_page_record_index"] for record in stored["records"]] == [0, 1, 0, 1, 0]
    assert stored["point_in_time_consistency_verified"] is False
    assert stored["global_nvd_completeness_attested"] is False
    assert stored["duplicate_cve_resolution_performed"] is False
    assert all(record["source_page_sha256"] for record in stored["records"])
    assert all("cvss_metrics" in record for record in stored["records"])
    assert result["output_sha256"] == hashlib.sha256(Path(result["output_path"]).read_bytes()).hexdigest()


def test_pure_inspection_does_not_persist_any_normalized_file(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    result = inspect_archived_nvd_query(tmp_path, query_id=query_id)
    assert result["record_count"] == 5
    assert not (tmp_path / "normalized").exists()


def test_idempotent_replay_preserves_bytes(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    first = normalize_archived_nvd_query(tmp_path, query_id=query_id)
    second = normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert first["status"] == "normalized"
    assert second["status"] == "verified_existing"
    assert first["output_sha256"] == second["output_sha256"]


def test_one_page_result_supported(tmp_path: Path) -> None:
    query_id = acquire(tmp_path, total=1)
    result = normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert result["pages_reconciled"] == 1
    assert result["record_count"] == 1


def test_two_page_result_supported(tmp_path: Path) -> None:
    query_id = acquire(tmp_path, total=4)
    result = normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert result["pages_reconciled"] == 2
    assert result["record_count"] == 4


@pytest.mark.parametrize("bad", ["../bad", "0" * 63, "Z" * 64, "", "a" * 65])
def test_invalid_query_id_rejected_before_any_file_write(tmp_path: Path, bad: str) -> None:
    with pytest.raises(NVDQueryNormalizationError, match="lowercase SHA-256"):
        normalize_archived_nvd_query(tmp_path, query_id=bad)
    assert not (tmp_path / "normalized").exists()


def test_missing_query_manifest_rejected(tmp_path: Path) -> None:
    with pytest.raises(NVDQueryNormalizationError, match="missing"):
        normalize_archived_nvd_query(tmp_path, query_id="a" * 64)


@pytest.mark.parametrize(
    "field,value,phrase",
    [
        ("reported_total_results", 30, "count mismatch"),
        ("unique_cve_count", 10, "count mismatch"),
        ("total_response_bytes", 1, "byte count mismatch"),
        ("pages_retrieved", 1, "count mismatch"),
        ("pagination_reconciled", False, "scope"),
        ("point_in_time_consistency_verified", True, "scope"),
        ("global_nvd_completeness_attested", True, "scope"),
        ("request_parameters", {}, "parameters"),
        ("query_sha256", "0" * 64, "SHA-256 mismatch"),
        ("first_page_request_url", "https://evil.example", "request"),
    ],
)
def test_query_manifest_tampering_fails_closed(
    tmp_path: Path, field: str, value: object, phrase: str
) -> None:
    query_id = acquire(tmp_path)
    modify_manifest(tmp_path, query_id, lambda m: m.__setitem__(field, value))
    with pytest.raises(NVDQueryNormalizationError, match=phrase):
        normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert not (tmp_path / "normalized").exists()


@pytest.mark.parametrize(
    "field,value,phrase",
    [
        ("start_index", 1, "start_index"),
        ("request_url", "https://evil.example", "request_url"),
        ("byte_count", 1, "byte_count"),
        ("raw_page_relative_path", "../../bad", "raw_page_relative_path"),
        ("response_timestamp", "wrong", "response_timestamp"),
    ],
)
def test_page_entry_tampering_fails_closed(
    tmp_path: Path, field: str, value: object, phrase: str
) -> None:
    query_id = acquire(tmp_path)
    modify_manifest(tmp_path, query_id, lambda m: m["pages"][0].__setitem__(field, value))
    with pytest.raises(NVDQueryNormalizationError, match=phrase):
        normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert not (tmp_path / "normalized").exists()


def test_missing_raw_page_fails_before_commit(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    data = json.loads(query_path(tmp_path, query_id).read_text())
    digest = data["pages"][1]["sha256"]
    (tmp_path / "raw" / "nvd" / digest / "page.json").unlink()
    with pytest.raises(NVDQueryNormalizationError, match="missing"):
        normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert not (tmp_path / "normalized").exists()


def test_corrupt_page_bytes_fail_before_commit(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    data = json.loads(query_path(tmp_path, query_id).read_text())
    digest = data["pages"][1]["sha256"]
    (tmp_path / "raw" / "nvd" / digest / "page.json").write_text("corrupt")
    with pytest.raises(NVDQueryNormalizationError, match="SHA-256 mismatch"):
        normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert not (tmp_path / "normalized").exists()


def test_raw_page_manifest_tamper_fails_before_commit(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    data = json.loads(query_path(tmp_path, query_id).read_text())
    digest = data["pages"][0]["sha256"]
    raw_manifest = tmp_path / "raw" / "nvd" / digest / "manifest.json"
    info = json.loads(raw_manifest.read_text())
    info["row_count"] = 99
    raw_manifest.write_text(json.dumps(info))
    with pytest.raises(NVDQueryNormalizationError, match="manifest mismatch: row_count"):
        normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert not (tmp_path / "normalized").exists()


def test_immutable_output_collision_rejected(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    result = normalize_archived_nvd_query(tmp_path, query_id=query_id)
    out = Path(result["output_path"])
    out.write_text("tampered", encoding="utf-8")
    with pytest.raises(NVDQueryNormalizationError, match="collision"):
        normalize_archived_nvd_query(tmp_path, query_id=query_id)
    assert out.read_text() == "tampered"


def test_cli_fails_closed_without_network(tmp_path: Path) -> None:
    assert main(["--query-id", "a" * 64, "--data-dir", str(tmp_path)]) == 1
    assert not (tmp_path / "normalized").exists()


def test_cli_normalizes_archived_query_and_verifies_replay(tmp_path: Path, capsys) -> None:
    query_id = acquire(tmp_path)
    assert main(["--query-id", query_id, "--data-dir", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "normalized"
    assert main(["--query-id", query_id, "--data-dir", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "verified_existing"


def test_existing_raw_archive_is_not_changed(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    manifest = json.loads(query_path(tmp_path, query_id).read_text())
    checksums = {}
    for page_info in manifest["pages"]:
        digest = page_info["sha256"]
        base = tmp_path / "raw" / "nvd" / digest
        checksums[digest] = (base / "page.json").read_bytes(), (base / "manifest.json").read_bytes()
    normalize_archived_nvd_query(tmp_path, query_id=query_id)
    for digest, (page_bytes, archive_bytes) in checksums.items():
        base = tmp_path / "raw" / "nvd" / digest
        assert (base / "page.json").read_bytes() == page_bytes
        assert (base / "manifest.json").read_bytes() == archive_bytes


def test_query_manifest_content_hash_mismatch_fails_even_with_valid_pages(tmp_path: Path) -> None:
    query_id = acquire(tmp_path)
    modify_manifest(tmp_path, query_id, lambda m: m["pages"].reverse())
    with pytest.raises(NVDQueryNormalizationError, match="content-addressed ID"):
        inspect_archived_nvd_query(tmp_path, query_id=query_id)


def test_conflicting_duplicate_cve_across_pages_is_rejected(tmp_path: Path) -> None:
    root = tmp_path
    request = build_nvd_request(
        last_mod_start="2026-11-12T00:00:00Z", last_mod_end="2026-11-13T00:00:00Z",
        results_per_page=2,
    )
    first = page(0, IDS[:2], total=4)
    # A forged query marker can make its counts look consistent, but duplicate
    # CVEs must still be rejected by normalization rather than deduplicated.
    second = page(2, (IDS[1], IDS[3]), total=4)
    first_archive = archive_nvd_page(root, page_bytes=first)
    second_archive = archive_nvd_page(root, page_bytes=second)
    hashes = [first_archive["page_sha256"], second_archive["page_sha256"]]
    query_sha = hashlib.sha256(request["url"].encode()).hexdigest()
    query_id = hashlib.sha256(_json_bytes({"query_sha256": query_sha, "pages": hashes})).hexdigest()
    metadata = [validate_nvd_page(first), validate_nvd_page(second)]
    contents = [first, second]
    entry_list = []
    for index, (raw, meta, digest) in enumerate(zip(contents, metadata, hashes, strict=True)):
        start = index * 2
        url = request["endpoint"] + "?" + urllib.parse.urlencode(
            sorted({**request["parameters"], "startIndex": str(start)}.items())
        )
        entry_list.append({
            "start_index": start, "results_per_page": 2, "row_count": meta["row_count"],
            "response_timestamp": meta["response_timestamp"], "request_url": url,
            "sha256": digest, "byte_count": len(raw),
            "raw_page_relative_path": f"raw/nvd/{digest}/page.json",
        })
    forged = {
        "format_version": QUERY_FORMAT_VERSION,
        "source": "NIST NVD CVE API 2.0", "acquisition_type": "explicit_bounded_https_paginated_query",
        "query_id": query_id, "acquired_at_utc": "2026-11-13T12:00:00.000Z",
        "query_sha256": query_sha, "query_mode": "last_modified_window",
        "first_page_request_url": request["url"], "request_parameters": request["parameters"],
        "requested_max_pages": 2, "pages_retrieved": 2, "pages": entry_list,
        "reported_total_results": 4, "unique_cve_count": 4,
        "total_response_bytes": len(first) + len(second),
        "pagination_reconciled": True,
        "scope": "query_pagination_vs_reported_total_only",
        "point_in_time_consistency_verified": False,
        "global_nvd_completeness_attested": False,
        "zero_result_queries_supported": False,
    }
    file = query_path(root, query_id)
    file.parent.mkdir(parents=True)
    file.write_bytes(_json_bytes(forged))
    with pytest.raises(NVDQueryNormalizationError, match="Duplicate CVE"):
        normalize_archived_nvd_query(root, query_id=query_id)
    assert not (root / "normalized").exists()
