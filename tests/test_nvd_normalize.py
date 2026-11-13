"""EA-03A3A offline, synthetic NVD normalization and archived-source tests."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from patchline.ingest.nvd import archive_nvd_page
from patchline.ingest.nvd_normalize import (
    NVDNormalizationError,
    main,
    normalize_archived_nvd_page,
    normalize_nvd_page,
)

FIXTURE = Path(__file__).parent / "fixtures" / "nvd-synthetic-page.json"


def sample() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def encoded(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")


def enriched() -> dict:
    page = sample()
    cve = page["vulnerabilities"][0]["cve"]
    cve["descriptions"].append({"lang": "fr", "value": "Exemple fictif."})
    cve["metrics"] = {
        "cvssMetricV2": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "baseSeverity": "MEDIUM",
                "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
            }
        ],
        "cvssMetricV30": [
            {
                "source": "source.example",
                "type": "Secondary",
                "cvssData": {"version": "3.0", "baseScore": 7.5, "baseSeverity": "HIGH"},
            }
        ],
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {"version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH"},
            },
            {
                "source": "other.example",
                "type": "Secondary",
                "cvssData": {"version": "3.1", "baseScore": 9.1, "baseSeverity": "CRITICAL"},
            },
        ],
        "cvssMetricV40": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "4.0",
                    "baseScore": 9.3,
                    "baseSeverity": "CRITICAL",
                    "attackVector": "NETWORK",
                },
            }
        ],
    }
    cve["weaknesses"] = [
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}
    ]
    cve["configurations"] = [
        {
            "nodes": [
                {
                    "operator": "AND",
                    "negate": True,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:fake:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0",
                            "versionEndExcluding": "2.0",
                            "matchCriteriaId": "00000000-0000-4000-8000-000000000000",
                        }
                    ],
                }
            ]
        }
    ]
    cve["references"] = [{"url": "https://example.invalid/advisory", "tags": ["Vendor Advisory"]}]
    return page


def test_fixture_yields_typed_rows_with_no_invented_severity() -> None:
    payload = FIXTURE.read_bytes()
    output = normalize_nvd_page(payload)
    assert output["format_version"] == "patchline.nvd-normalized-page.v1"
    assert output["source_page_sha256"] == hashlib.sha256(payload).hexdigest()
    assert output["record_count"] == 2
    assert output["source_reported_total_results"] == 2
    first, second = output["records"]
    assert first["cve_id"] == "CVE-2026-12345"
    assert first["source_identifier"] == "example.invalid"
    assert first["cvss_metrics"] == []
    assert first["missing"]["cvss_metrics"] is True
    assert second["vuln_status"] == "Awaiting Analysis"
    assert second["source_identifier"] is None
    assert not output["global_nvd_completeness_attested"]
    assert not output["point_in_time_consistency_verified"]
    assert not output["organization_asset_exposure_known"]
    assert not output["source_origin_independently_verified"]


def test_multiple_cvss_versions_sources_and_missing_fields_are_not_collapsed() -> None:
    output = normalize_nvd_page(encoded(enriched()))
    metrics = output["records"][0]["cvss_metrics"]
    assert len(metrics) == 5
    assert [m["cvss_version"] for m in metrics] == ["2.0", "3.0", "3.1", "3.1", "4.0"]
    assert [m["base_score"] for m in metrics] == [5.0, 7.5, 8.8, 9.1, 9.3]
    assert metrics[0]["base_severity"] == "MEDIUM"
    assert metrics[2]["source"] != metrics[3]["source"]
    assert metrics[4]["source_metric"]["cvssData"]["attackVector"] == "NETWORK"
    assert output["records"][0]["missing"]["cvss_metrics"] is False


def test_nested_cpe_and_weakness_provenance_preserved_without_flattening() -> None:
    page = enriched()
    row = normalize_nvd_page(encoded(page))["records"][0]
    raw = page["vulnerabilities"][0]["cve"]
    assert row["configurations"] == raw["configurations"]
    assert row["weaknesses"] == raw["weaknesses"]
    assert row["references"] == raw["references"]
    assert row["configurations"][0]["nodes"][0]["negate"] is True
    assert row["missing"]["configurations"] is False


def test_source_timestamps_preserved_verbatim_without_timezone_guess() -> None:
    row = normalize_nvd_page(encoded(enriched()))["records"][0]
    assert row["published_source_timestamp"] == "2026-11-01T00:00:00.000"
    assert row["modified_source_timestamp"] == "2026-11-12T00:00:00.000"


def test_multilingual_descriptions_preserved_and_no_translation() -> None:
    page = enriched()
    page["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "fr", "value": "Exemple seulement."}
    ]
    row = normalize_nvd_page(encoded(page))["records"][0]
    assert row["description_en"] is None
    assert row["descriptions"] == [{"lang": "fr", "value": "Exemple seulement."}]
    assert row["missing"]["english_description"] is True


@pytest.mark.parametrize(
    "edit,phrase",
    [
        (lambda x: x["vulnerabilities"][0]["cve"]["descriptions"].append({"lang": 7, "value": "X"}), "description"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV31={}), "array"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV31=[{}]), "cvssData"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV31=[{"cvssData": {"version": "4.0"}}]), "version"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV31=[{"cvssData": {"version": "3.1", "baseScore": True}}]), "score"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV31=[{"cvssData": {"version": "3.1", "baseScore": 14}}]), "score"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV31=[{"cvssData": {"version": "3.1", "baseSeverity": 4}}]), "text"),
        (lambda x: x["vulnerabilities"][0]["cve"]["metrics"].update(cvssMetricV5=[]), "unsupported"),
        (lambda x: x["vulnerabilities"][0]["cve"].update(configurations=["invalid"]), "object"),
        (lambda x: x["vulnerabilities"][0]["cve"].update(weaknesses=["invalid"]), "object"),
        (lambda x: x["vulnerabilities"][0]["cve"].update(references=["invalid"]), "object"),
    ],
)
def test_bad_nested_structures_fail_closed(edit, phrase: str) -> None:
    page = enriched()
    edit(page)
    with pytest.raises(NVDNormalizationError, match=phrase):
        normalize_nvd_page(encoded(page))


def test_source_response_validator_blocks_duplicate_cve_ids() -> None:
    page = sample()
    page["vulnerabilities"][1]["cve"]["id"] = page["vulnerabilities"][0]["cve"]["id"]
    with pytest.raises(NVDNormalizationError, match="Duplicate CVE"):
        normalize_nvd_page(encoded(page))


def test_archived_page_normalizes_once_and_replay_is_identical(tmp_path: Path) -> None:
    archived = archive_nvd_page(tmp_path, page_bytes=FIXTURE.read_bytes())
    first = normalize_archived_nvd_page(tmp_path, snapshot_id=archived["snapshot_id"])
    repeat = normalize_archived_nvd_page(tmp_path, snapshot_id=archived["snapshot_id"])
    assert first["status"] == "normalized"
    assert repeat["status"] == "verified_existing"
    assert first["normalized_sha256"] == repeat["normalized_sha256"]
    output = json.loads(Path(first["output_path"]).read_text(encoding="utf-8"))
    assert output["record_count"] == 2
    assert output["source_archive_manifest_sha256"] == hashlib.sha256(
        (Path(archived["snapshot_path"]) / "manifest.json").read_bytes()
    ).hexdigest()
    assert output["source_page_relative_path"].endswith("/page.json")


def test_corrupt_normalized_result_is_never_overwritten(tmp_path: Path) -> None:
    archived = archive_nvd_page(tmp_path, page_bytes=FIXTURE.read_bytes())
    first = normalize_archived_nvd_page(tmp_path, snapshot_id=archived["snapshot_id"])
    output = Path(first["output_path"])
    output.write_text("tampered", encoding="utf-8")
    with pytest.raises(NVDNormalizationError, match="collision"):
        normalize_archived_nvd_page(tmp_path, snapshot_id=archived["snapshot_id"])
    assert output.read_text(encoding="utf-8") == "tampered"


def test_corrupt_archived_page_fails_without_creating_output(tmp_path: Path) -> None:
    archived = archive_nvd_page(tmp_path, page_bytes=FIXTURE.read_bytes())
    (Path(archived["snapshot_path"]) / "page.json").write_text("altered", encoding="utf-8")
    with pytest.raises(NVDNormalizationError, match="SHA-256 mismatch"):
        normalize_archived_nvd_page(tmp_path, snapshot_id=archived["snapshot_id"])
    assert not (tmp_path / "normalized").exists()


def test_corrupt_source_manifest_fails_without_creating_output(tmp_path: Path) -> None:
    archived = archive_nvd_page(tmp_path, page_bytes=FIXTURE.read_bytes())
    marker = Path(archived["snapshot_path"]) / "manifest.json"
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    manifest["row_count"] = 5
    marker.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(NVDNormalizationError, match="manifest mismatch: row_count"):
        normalize_archived_nvd_page(tmp_path, snapshot_id=archived["snapshot_id"])
    assert not (tmp_path / "normalized").exists()


@pytest.mark.parametrize("identifier", ["../bad", "ABC", "A" * 64, "0" * 63])
def test_bad_snapshot_identifier_rejected_before_filesystem_access(
    tmp_path: Path, identifier: str
) -> None:
    with pytest.raises(NVDNormalizationError, match="lowercase SHA-256"):
        normalize_archived_nvd_page(tmp_path, snapshot_id=identifier)


def test_missing_source_fails_without_output(tmp_path: Path) -> None:
    with pytest.raises(NVDNormalizationError, match="missing"):
        normalize_archived_nvd_page(tmp_path, snapshot_id="a" * 64)


def test_cli_fails_closed_for_invalid_source_and_never_fetches_network(tmp_path: Path) -> None:
    assert main(["--snapshot-id", "a" * 64, "--data-dir", str(tmp_path)]) == 1
    assert not (tmp_path / "normalized").exists()


def test_source_record_not_mutated() -> None:
    page = enriched()
    before = copy.deepcopy(page)
    normalize_nvd_page(encoded(page))
    assert page == before
