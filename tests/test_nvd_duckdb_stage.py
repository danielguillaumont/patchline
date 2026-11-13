"""EA-03A4A: fully offline, source-pinned NVD DuckDB staging tests."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import duckdb
import pytest

from patchline.ingest.nvd_acquire import build_nvd_request
from patchline.ingest.nvd_pagination import acquire_nvd_query
from patchline.ingest.nvd_query_normalize import normalize_archived_nvd_query
from patchline.warehouse.nvd_stage import (
    NVDWarehouseError,
    main,
    stage_nvd_query,
)

IDS = ("CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003")


def _page(start: int, ids: tuple[str, ...], *, include_metrics: bool) -> bytes:
    records = []
    for number, cve_id in enumerate(ids):
        cve = {
            "id": cve_id, "sourceIdentifier": "synthetic.example",
            "published": "2026-11-01T00:00:00.000",
            "lastModified": "2026-11-12T00:00:00.000", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Synthetic example, not a real finding"}],
        }
        if include_metrics and start == 0 and number == 0:
            cve["metrics"] = {
                "cvssMetricV2": [{"source": "test", "type": "Secondary", "cvssData": {
                    "version": "2.0", "baseScore": 4.3, "vectorString": "AV:N/AC:M/Au:N/C:N/I:P/A:N"}}],
                "cvssMetricV30": [{"source": "test", "type": "Secondary", "cvssData": {
                    "version": "3.0", "baseScore": 6.4, "baseSeverity": "MEDIUM"}}],
                "cvssMetricV31": [{"source": "test", "type": "Primary", "cvssData": {
                    "version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}}],
                "cvssMetricV40": [{"source": "test", "type": "Primary", "cvssData": {
                    "version": "4.0", "baseSeverity": "HIGH"}}],
            }
            cve["weaknesses"] = [{"source": "test", "description": [{"lang": "en", "value": "CWE-79"}]}]
            cve["configurations"] = [{"nodes": [{"operator": "AND", "negate": False}]}]
            cve["references"] = [{"url": "https://example.org/reference"}]
        records.append({"cve": cve})
    return json.dumps({
        "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-11-13T12:00:00.000",
        "resultsPerPage": 2, "startIndex": start, "totalResults": 3,
        "vulnerabilities": records,
    }, sort_keys=True).encode("utf-8")


def _prepared(tmp_path: Path, *, include_metrics: bool = True) -> str:
    request = build_nvd_request(
        last_mod_start="2026-11-12T00:00:00Z",
        last_mod_end="2026-11-13T00:00:00Z", results_per_page=2,
    )

    def fake_fetch(url: str, _key: str | None, _timeout: int) -> bytes:
        start = int(parse_qs(urlsplit(url).query)["startIndex"][0])
        return _page(start, IDS[start : start + 2], include_metrics=include_metrics)

    obtained = acquire_nvd_query(
        tmp_path, request=request, max_pages=2, fetch=fake_fetch,
        sleep=lambda _: None, now=lambda: datetime(2026, 11, 13, 12, tzinfo=UTC),
    )
    query_id = obtained["query_id"]
    normalize_archived_nvd_query(tmp_path, query_id=query_id)
    return query_id


def _database(tmp_path: Path, query_id: str) -> Path:
    return tmp_path / "warehouse" / "nvd-queries" / f"{query_id}.duckdb"


def test_stages_all_cves_with_source_lineage_and_cvss_versions(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    result = stage_nvd_query(tmp_path, query_id=query_id)
    assert result["status"] == "staged"
    assert result["cve_count"] == 3
    assert result["cvss_metric_count"] == 4
    assert result["point_in_time_consistency_verified"] is False
    with duckdb.connect(str(_database(tmp_path, query_id)), read_only=True) as con:
        registry = con.execute("SELECT contract_version, record_count, metric_count, "
                               "point_in_time_consistency_verified "
                               "FROM nvd_stage.query_registry").fetchone()
        assert registry == ("patchline.nvd-duckdb-query-staging.v1", 3, 4, False)
        cves = con.execute("SELECT cve_id, record_index, source_page_start_index, "
                           "source_page_record_index, source_page_sha256 "
                           "FROM nvd_stage.cves ORDER BY record_index").fetchall()
        assert [row[0] for row in cves] == list(IDS)
        assert [row[1:4] for row in cves] == [(0, 0, 0), (1, 0, 1), (2, 2, 0)]
        assert all(len(row[4]) == 64 for row in cves)
        metrics = con.execute("SELECT cvss_version, base_score FROM nvd_stage.cvss_metrics "
                              "ORDER BY metric_index").fetchall()
        assert metrics == [("2.0", 4.3), ("3.0", 6.4), ("3.1", 7.5), ("4.0", None)]
        source_json = con.execute("SELECT record_json FROM nvd_stage.cves "
                                  "WHERE cve_id = ?", [IDS[0]]).fetchone()[0]
        original = json.loads(source_json)
        assert original["configurations"][0]["nodes"][0]["operator"] == "AND"
        assert original["weaknesses"][0]["description"][0]["value"] == "CWE-79"


def test_preserves_missingness_and_no_score_imputation(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path, include_metrics=False)
    stage_nvd_query(tmp_path, query_id=query_id)
    with duckdb.connect(str(_database(tmp_path, query_id)), read_only=True) as con:
        assert con.execute("SELECT COUNT(*) FROM nvd_stage.cvss_metrics").fetchone()[0] == 0
        flags = con.execute("SELECT missing_cvss_metrics, missing_weaknesses, "
                            "missing_configurations, missing_references "
                            "FROM nvd_stage.cves").fetchall()
        assert flags == [(True, True, True, True)] * 3


def test_identical_replay_never_rewrites_warehouse(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    first = stage_nvd_query(tmp_path, query_id=query_id)
    database = _database(tmp_path, query_id)
    previous_hash = hashlib.sha256(database.read_bytes()).hexdigest()
    second = stage_nvd_query(tmp_path, query_id=query_id)
    assert first["status"] == "staged"
    assert second["status"] == "verified_existing"
    assert second["normalized_sha256"] == first["normalized_sha256"]
    assert hashlib.sha256(database.read_bytes()).hexdigest() == previous_hash


def test_existing_database_data_corruption_fails_closed(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    stage_nvd_query(tmp_path, query_id=query_id)
    database = _database(tmp_path, query_id)
    with duckdb.connect(str(database)) as con:
        con.execute("UPDATE nvd_stage.cves SET vuln_status = 'TAMPERED' WHERE record_index = 1")
    with pytest.raises(NVDWarehouseError, match="row or lineage mismatch"):
        stage_nvd_query(tmp_path, query_id=query_id)
    with duckdb.connect(str(database), read_only=True) as con:
        assert con.execute("SELECT vuln_status FROM nvd_stage.cves WHERE record_index = 1").fetchone()[0] == "TAMPERED"


def test_existing_database_extra_row_fails_closed(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    stage_nvd_query(tmp_path, query_id=query_id)
    database = _database(tmp_path, query_id)
    with duckdb.connect(str(database)) as con:
        con.execute("DELETE FROM nvd_stage.cvss_metrics WHERE metric_index = 0")
    with pytest.raises(NVDWarehouseError, match="row or lineage mismatch"):
        stage_nvd_query(tmp_path, query_id=query_id)


def test_modified_normalized_bytes_fail_before_database_write(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    normalized = tmp_path / "normalized" / "nvd-queries" / query_id / "normalized.json"
    normalized.write_text(normalized.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(NVDWarehouseError, match="normalized|Normalized"):
        stage_nvd_query(tmp_path, query_id=query_id)
    assert not _database(tmp_path, query_id).exists()


def test_modified_raw_source_fails_before_database_write(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    raw_manifest = json.loads((tmp_path / "raw" / "nvd-queries" / query_id / "manifest.json").read_text())
    first_digest = raw_manifest["pages"][0]["sha256"]
    page = tmp_path / "raw" / "nvd" / first_digest / "page.json"
    page.write_bytes(b"modified")
    with pytest.raises(NVDWarehouseError, match="source verification failed"):
        stage_nvd_query(tmp_path, query_id=query_id)
    assert not _database(tmp_path, query_id).exists()


@pytest.mark.parametrize("bad", ["../foo", "Z" * 64, "0" * 63, "", "x" * 65])
def test_bad_identifier_does_not_write(tmp_path: Path, bad: str) -> None:
    with pytest.raises(NVDWarehouseError, match="lowercase SHA-256"):
        stage_nvd_query(tmp_path, query_id=bad)
    assert not (tmp_path / "warehouse").exists()


def test_missing_normalized_query_fails_closed(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    normalized = tmp_path / "normalized" / "nvd-queries" / query_id / "normalized.json"
    normalized.unlink()
    with pytest.raises(NVDWarehouseError, match="missing"):
        stage_nvd_query(tmp_path, query_id=query_id)
    assert not _database(tmp_path, query_id).exists()


def test_alternate_output_path_does_not_modify_kev_epss_database(tmp_path: Path) -> None:
    query_id = _prepared(tmp_path)
    separate = tmp_path / "custom" / "nvd-only.duckdb"
    unrelated = tmp_path / "existing.duckdb"
    with duckdb.connect(str(unrelated)) as con:
        con.execute("CREATE TABLE unrelated (value INTEGER)")
        con.execute("INSERT INTO unrelated VALUES (17)")
    result = stage_nvd_query(tmp_path, query_id=query_id, database=separate)
    assert Path(result["database_path"]) == separate
    with duckdb.connect(str(unrelated), read_only=True) as con:
        assert con.execute("SELECT value FROM unrelated").fetchall() == [(17,)]
    with pytest.raises(NVDWarehouseError, match="Staging"):
        stage_nvd_query(tmp_path, query_id=query_id, database=unrelated)


def test_cli_returns_json_and_replay_status(tmp_path: Path, capsys) -> None:
    query_id = _prepared(tmp_path)
    for expected in ("staged", "verified_existing"):
        assert main(["--data-dir", str(tmp_path), "--query-id", query_id]) == 0
        output = json.loads(capsys.readouterr().out)
        assert output["status"] == expected
        assert output["cve_count"] == 3


def test_cli_missing_source_fails_cleanly(tmp_path: Path, capsys) -> None:
    assert main(["--data-dir", str(tmp_path), "--query-id", "a" * 64]) == 1
    assert "failed" in capsys.readouterr().err
    assert not (tmp_path / "warehouse").exists()
