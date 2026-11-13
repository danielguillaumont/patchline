"""Guardrails for source-pinned, noncausal archived-source research reports."""

from __future__ import annotations

from copy import deepcopy

import pytest

from patchline.research.case_study import ResearchError, render_report

KEV = "a" * 64
EPSS = "b" * 64


def fixture() -> tuple[dict, dict]:
    manifest = {
        "schema_id": "patchline.analytics-export.v2",
        "data_kind": "archived_source_snapshots",
        "artifacts": [{}] * 12,
        "source_snapshots": [
            {"source": "epss", "source_date": "2026-11-11", "snapshot_id": EPSS,
             "retrieved_at_utc": "2026-11-11T12:00:00Z", "model_version": "v-test",
             "row_count": 4},
            {"source": "kev", "source_date": "2026-11-10", "snapshot_id": KEV,
             "retrieved_at_utc": "2026-11-10T12:00:00Z", "model_version": None,
             "row_count": 3},
        ],
    }
    labels = ["0.000 to <0.001", "0.001 to <0.010", "0.010 to <0.100",
              "0.100 to <0.500", "0.500 to 1.000 inclusive"]
    full_counts = [1, 0, 1, 0, 2]
    kev_counts = [0, 0, 1, 0, 1, 1]
    datasets = {
        "m03_epss_coverage_of_kev": [{
            "denominator_total_kev": 3, "numerator_matched_kev": 2, "unmatched_kev": 1,
        }],
        "m04_epss_population_summary": [{"scored_cve_count": 4}],
        "m04_epss_score_bands": [
            {"band_order": i + 1, "band_label": labels[i], "cve_count": full_counts[i],
             "lower_bound": [0, 0.001, 0.01, 0.1, 0.5][i],
             "upper_bound": [0.001, 0.01, 0.1, 0.5, 1][i],
             "upper_inclusive": i == 4}
            for i in range(5)
        ],
        "m05_kev_epss_cohort_bands": [
            {"band_order": i + 1, "band_label": labels[i],
             "kev_cve_count": kev_counts[i], "full_epss_band_count": full_counts[i],
             "cohort_category": "scored_band"}
            for i in range(5)
        ] + [{"band_order": 6, "band_label": "No matching EPSS score",
              "kev_cve_count": kev_counts[5], "cohort_category": "unscored_kev"}],
    }
    return manifest, datasets


def render(manifest: dict, datasets: dict) -> str:
    return render_report(manifest, datasets, kev_snapshot=KEV, epss_snapshot=EPSS)


def test_renders_reconciled_distribution_and_honest_limits() -> None:
    manifest, datasets = fixture()
    text = render(manifest, datasets)
    assert "2 of 3 KEV CVEs (66.67%)" in text
    assert "1 of 2 scored KEV CVEs (50.00%)" in text
    assert "2 of 4 scored CVEs in the full EPSS population (50.00%)" in text
    assert "0.010 to <0.100" in text
    assert "**Unscored KEV:** 1 of 3 (33.33% of all KEV)" in text
    assert "not independent" in text
    assert "separate **synthetic fixture**" in text
    assert "\u2014" not in text


def test_rejects_synthetic_classification() -> None:
    manifest, datasets = fixture()
    manifest["data_kind"] = "synthetic_fixture"
    with pytest.raises(ResearchError, match="must not use synthetic"):
        render(manifest, datasets)


def test_rejects_wrong_source_pair() -> None:
    manifest, datasets = fixture()
    manifest["source_snapshots"][0]["snapshot_id"] = "c" * 64
    with pytest.raises(ResearchError, match="requested IDs"):
        render(manifest, datasets)


def test_rejects_broken_band_totals() -> None:
    manifest, datasets = fixture()
    datasets["m04_epss_score_bands"][0]["cve_count"] = 2
    with pytest.raises(ResearchError, match="Score band totals"):
        render(manifest, datasets)


def test_rejects_kev_disagreement() -> None:
    manifest, datasets = fixture()
    datasets["m05_kev_epss_cohort_bands"][5]["kev_cve_count"] = 0
    with pytest.raises(ResearchError, match="Unmatched KEV totals"):
        render(manifest, datasets)


def test_rejects_wrong_high_band_threshold() -> None:
    manifest, datasets = fixture()
    datasets["m04_epss_score_bands"][4]["lower_bound"] = 0.4
    with pytest.raises(ResearchError, match="High-band threshold"):
        render(manifest, datasets)


def test_rejects_noncontiguous_band_orders() -> None:
    manifest, datasets = fixture()
    datasets["m05_kev_epss_cohort_bands"][1]["band_order"] = 4
    with pytest.raises(ResearchError, match="ordered 1 through 6"):
        render(manifest, datasets)


def test_rejects_inconsistent_source_row_counts() -> None:
    manifest, datasets = fixture()
    manifest["source_snapshots"][1]["row_count"] = 4
    with pytest.raises(ResearchError, match="Source record counts"):
        render(manifest, datasets)


def test_report_deterministic_and_does_not_mutate_input() -> None:
    manifest, datasets = fixture()
    original = deepcopy((manifest, datasets))
    assert render(manifest, datasets) == render(manifest, datasets)
    assert (manifest, datasets) == original
