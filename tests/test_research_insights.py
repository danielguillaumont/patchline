"""Evidence-first, local-only, source-pinned insight generation tests."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from types import SimpleNamespace

import pytest

from patchline.research.case_study import ResearchError
from patchline.research.insights import (
    SCHEMA_ID,
    build_insight_pack,
    create_insight_pack,
    verify_insight_pack,
)

KEV = "a" * 64
EPSS = "b" * 64


def small_fixture() -> tuple[dict, dict]:
    labels = [
        "0.000 to <0.001", "0.001 to <0.010", "0.010 to <0.100",
        "0.100 to <0.500", "0.500 to 1.000 inclusive",
    ]
    full_counts = [1, 0, 1, 0, 2]
    kev_counts = [0, 0, 1, 0, 1, 1]
    manifest = {
        "schema_id": "patchline.analytics-export.v2",
        "data_kind": "archived_source_snapshots",
        "artifacts": [{}] * 12,
        "source_snapshots": [
            {
                "source": "kev", "snapshot_id": KEV, "row_count": 3,
                "source_date": "2026-11-10", "retrieved_at_utc": "2026-11-11T12:00:00Z",
                "model_version": None,
            },
            {
                "source": "epss", "snapshot_id": EPSS, "row_count": 4,
                "source_date": "2026-11-11", "retrieved_at_utc": "2026-11-11T12:00:00Z",
                "model_version": "v-test",
            },
        ],
    }
    datasets = {
        "m03_epss_coverage_of_kev": [{
            "denominator_total_kev": 3, "numerator_matched_kev": 2,
            "unmatched_kev": 1,
        }],
        "m04_epss_population_summary": [{"scored_cve_count": 4}],
        "m04_epss_score_bands": [
            {
                "band_order": i + 1, "band_label": labels[i],
                "cve_count": full_counts[i],
                "lower_bound": [0, 0.001, 0.01, 0.1, 0.5][i],
                "upper_bound": [0.001, 0.01, 0.1, 0.5, 1][i],
                "upper_inclusive": i == 4,
            }
            for i in range(5)
        ],
        "m05_kev_epss_cohort_bands": [
            {
                "band_order": i + 1, "band_label": labels[i],
                "kev_cve_count": kev_counts[i],
                "full_epss_band_count": full_counts[i],
                "cohort_category": "scored_band",
            }
            for i in range(5)
        ] + [{
            "band_order": 6, "band_label": "No matching EPSS score",
            "kev_cve_count": 1, "cohort_category": "unscored_kev",
        }],
    }
    return manifest, datasets


def build(manifest: dict, datasets: dict) -> dict:
    return build_insight_pack(
        manifest, datasets, kev_snapshot=KEV, epss_snapshot=EPSS
    )


def published_count_fixture() -> tuple[dict, dict]:
    """In-memory numerical regression, not an independently verified real-data export."""
    manifest, data = small_fixture()
    manifest["source_snapshots"][0]["row_count"] = 1779
    manifest["source_snapshots"][1]["row_count"] = 404864
    data["m03_epss_coverage_of_kev"][0].update({
        "denominator_total_kev": 1779,
        "numerator_matched_kev": 1779,
        "unmatched_kev": 0,
    })
    data["m04_epss_population_summary"][0]["scored_cve_count"] = 404864
    full_counts = [3306, 252693, 131324, 13159, 4382]
    kev_counts = [0, 58, 383, 429, 909]
    for i in range(5):
        data["m04_epss_score_bands"][i]["cve_count"] = full_counts[i]
        data["m05_kev_epss_cohort_bands"][i]["kev_cve_count"] = kev_counts[i]
        data["m05_kev_epss_cohort_bands"][i]["full_epss_band_count"] = full_counts[i]
    data["m05_kev_epss_cohort_bands"][5]["kev_cve_count"] = 0
    return manifest, data


def test_local_only_contract_and_provenance() -> None:
    manifest, data = small_fixture()
    pack = build(manifest, data)
    assert pack["schema_id"] == SCHEMA_ID
    assert pack["public_release_approved"] is False
    assert pack["publication_scope"] == "local_review_only"
    assert pack["data_kind"] == "archived_source_snapshots"
    assert [s["snapshot_id"] for s in pack["source_snapshots"]] == [KEV, EPSS]
    assert len(pack["insights"]) == 3
    assert all(i["caveat"] and i["next_question"] for i in pack["insights"])
    assert "overlap" in pack["insights"][0]["caveat"]


def test_equal_distribution_never_claims_kev_is_higher() -> None:
    manifest, data = small_fixture()
    pack = build(manifest, data)
    assert "equal shares" in pack["insights"][0]["headline"]
    assert pack["insights"][0]["measures"][0]["share_percent"] == "50.00"
    assert pack["insights"][0]["measures"][1]["share_percent"] == "50.00"
    assert "Some KEV records" in pack["insights"][1]["headline"]
    assert "66.67%" in pack["insights"][1]["plain_language"]


def test_archived_published_counts_generate_correct_findings() -> None:
    manifest, data = published_count_fixture()
    pack = build(manifest, data)
    high = pack["insights"][0]
    above = pack["insights"][2]
    assert "larger share" in high["headline"]
    assert [m["share_percent"] for m in high["measures"]] == ["51.10", "1.08"]
    assert [m["share_percent"] for m in above["measures"]] == ["75.21", "4.33"]
    assert "All KEV records" in pack["insights"][1]["headline"]
    assert "1,779 of 1,779" in pack["insights"][1]["plain_language"]


def test_deterministic_and_does_not_mutate_inputs() -> None:
    manifest, data = published_count_fixture()
    previous = deepcopy((manifest, data))
    first = build(manifest, data)
    assert first == build(manifest, data)
    assert (manifest, data) == previous
    assert "attack forecast" in first["insights"][0]["caveat"]


def test_rejects_synthetic_input_and_wrong_pinned_source() -> None:
    manifest, data = small_fixture()
    manifest["data_kind"] = "synthetic_fixture"
    with pytest.raises(ResearchError, match="must not use synthetic"):
        build(manifest, data)
    manifest["data_kind"] = "archived_source_snapshots"
    manifest["source_snapshots"][0]["snapshot_id"] = "c" * 64
    with pytest.raises(ResearchError, match="requested IDs"):
        build(manifest, data)


def test_rejects_inconsistent_denominators_and_threshold() -> None:
    manifest, data = small_fixture()
    data["m03_epss_coverage_of_kev"][0]["numerator_matched_kev"] = 3
    with pytest.raises(ResearchError):
        build(manifest, data)
    manifest, data = small_fixture()
    data["m04_epss_score_bands"][4]["lower_bound"] = 0.4
    with pytest.raises(ResearchError, match="High-band threshold"):
        build(manifest, data)


def test_wrong_source_classification_never_generates_pack() -> None:
    manifest, data = small_fixture()
    manifest["schema_id"] = "patchline.analytics-export.v1"
    with pytest.raises(ResearchError, match="explicit v2"):
        build(manifest, data)


def _fake_export(monkeypatch: pytest.MonkeyPatch, tmp_path):
    manifest, data = small_fixture()
    directory = tmp_path / "verified-fixture"
    directory.mkdir()
    for name, rows in data.items():
        (directory / f"{name}.json").write_text(json.dumps(rows), encoding="utf-8")
    # Inject a harmless stand-in for the heavyweight verifier only in unit tests.
    # In actual CLI use the real verify_bundle validates every artifact.
    monkeypatch.setitem(
        sys.modules, "patchline.exports.analytics",
        SimpleNamespace(verify_bundle=lambda _export: deepcopy(manifest)),
    )
    return directory


def test_create_verify_exclusive_write_and_byte_tamper(monkeypatch, tmp_path) -> None:
    directory = _fake_export(monkeypatch, tmp_path)
    target = tmp_path / "review" / "insights.json"
    initial = create_insight_pack(
        directory, target, kev_snapshot=KEV, epss_snapshot=EPSS
    )
    assert target.read_bytes() == initial
    assert initial.endswith(b"\n")
    verify_insight_pack(directory, target, kev_snapshot=KEV, epss_snapshot=EPSS)
    with pytest.raises(ResearchError, match="overwrite"):
        create_insight_pack(directory, target, kev_snapshot=KEV, epss_snapshot=EPSS)
    target.write_bytes(initial.replace(b"local_review_only", b"public_approved"))
    with pytest.raises(ResearchError, match="differs"):
        verify_insight_pack(directory, target, kev_snapshot=KEV, epss_snapshot=EPSS)


def test_creation_rejects_repository_output_and_relative_path(monkeypatch, tmp_path) -> None:
    directory = _fake_export(monkeypatch, tmp_path)
    repository = __import__("pathlib").Path(__file__).resolve().parents[1]
    with pytest.raises(ResearchError, match="inside repository"):
        create_insight_pack(
            directory, repository / "unsafe-insights.json",
            kev_snapshot=KEV, epss_snapshot=EPSS,
        )
    with pytest.raises(ResearchError, match="absolute"):
        create_insight_pack(
            directory, __import__("pathlib").Path("relative.json"),
            kev_snapshot=KEV, epss_snapshot=EPSS,
        )
