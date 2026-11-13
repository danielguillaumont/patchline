"""Generate a local research brief from a verified, archived-source v2 export.

The report is intentionally not automatically published. Verify its content and
source pair before promoting a reviewed copy into public documentation.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


class ResearchError(ValueError):
    """An input or publication invariant for the research brief was violated."""


MODEL_ROWS = {
    "m03_epss_coverage_of_kev": 1,
    "m04_epss_population_summary": 1,
    "m04_epss_score_bands": 5,
    "m05_kev_epss_cohort_bands": 6,
}


def _rows(directory: Path, model: str, count: int) -> list[dict[str, Any]]:
    path = directory / f"{model}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, list) or len(value) != count
            or any(not isinstance(row, dict) for row in value)):
        raise ResearchError(f"Unexpected record count or shape: {model}")
    return value


def _percentage(numerator: int, denominator: int) -> str:
    return "N/A" if denominator == 0 else f"{100 * numerator / denominator:.2f}%"


def _integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ResearchError(f"Invalid count: {field}")
    return value


def _check_source_pair(manifest: dict[str, Any], kev_id: str, epss_id: str) -> dict[str, dict]:
    if manifest.get("schema_id") != "patchline.analytics-export.v2":
        raise ResearchError("Research brief requires an explicit v2 export")
    if manifest.get("data_kind") != "archived_source_snapshots":
        raise ResearchError("Research brief must not use synthetic fixture data")
    sources = manifest.get("source_snapshots")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ResearchError("Expected exactly two source snapshots")
    by_source = {row["source"]: row for row in sources}
    if set(by_source) != {"kev", "epss"}:
        raise ResearchError("Expected one KEV and one EPSS snapshot")
    if (by_source["kev"]["snapshot_id"] != kev_id
            or by_source["epss"]["snapshot_id"] != epss_id):
        raise ResearchError("Verified source pair differs from explicitly requested IDs")
    return by_source


def render_report(
    manifest: dict[str, Any], datasets: dict[str, list[dict[str, Any]]],
    *, kev_snapshot: str, epss_snapshot: str,
) -> str:
    """Render source-pinned descriptive findings, without causal or risk claims."""
    sources = _check_source_pair(manifest, kev_snapshot, epss_snapshot)
    if set(datasets) != set(MODEL_ROWS):
        raise ResearchError("Research dataset inventory mismatch")
    if any(len(datasets[key]) != count for key, count in MODEL_ROWS.items()):
        raise ResearchError("Research mart row counts do not match v2 contract")
    m03 = datasets["m03_epss_coverage_of_kev"][0]
    m04 = datasets["m04_epss_population_summary"][0]
    bands = datasets["m04_epss_score_bands"]
    cohort = datasets["m05_kev_epss_cohort_bands"]
    total_kev = _integer(m03["denominator_total_kev"], "KEV total")
    matched = _integer(m03["numerator_matched_kev"], "matched KEV")
    unmatched = _integer(m03["unmatched_kev"], "unmatched KEV")
    full = _integer(m04["scored_cve_count"], "EPSS total")
    if total_kev == 0 or matched == 0 or full == 0:
        raise ResearchError("Research comparison requires nonempty scored populations")
    if matched + unmatched != total_kev:
        raise ResearchError("KEV coverage does not reconcile")
    if (total_kev != sources["kev"]["row_count"]
            or full != sources["epss"]["row_count"]):
        raise ResearchError("Source record counts do not reconcile")
    if [r["band_order"] for r in bands] != [1, 2, 3, 4, 5]:
        raise ResearchError("EPSS bands are not ordered 1 through 5")
    if [r["band_order"] for r in cohort] != [1, 2, 3, 4, 5, 6]:
        raise ResearchError("KEV cohort bands are not ordered 1 through 6")
    epss_counts = [_integer(r["cve_count"], "EPSS band") for r in bands]
    kev_counts = [_integer(r["kev_cve_count"], "KEV band") for r in cohort]
    if sum(epss_counts) != full or sum(kev_counts[:5]) != matched:
        raise ResearchError("Score band totals do not reconcile")
    if kev_counts[5] != unmatched or sum(kev_counts) != total_kev:
        raise ResearchError("Unmatched KEV totals do not reconcile")
    for idx in range(5):
        if (bands[idx]["band_label"] != cohort[idx]["band_label"]
                or cohort[idx]["full_epss_band_count"] != epss_counts[idx]):
            raise ResearchError("KEV and EPSS band definitions differ")
    if (cohort[5]["cohort_category"] != "unscored_kev"
            or cohort[5]["band_label"] != "No matching EPSS score"):
        raise ResearchError("The sixth KEV row must be an unscored category")
    high_band = bands[4]
    if (not math.isclose(high_band["lower_bound"], 0.5, abs_tol=1e-12)
            or not math.isclose(high_band["upper_bound"], 1.0, abs_tol=1e-12)
            or high_band["upper_inclusive"] is not True):
        raise ResearchError("High-band threshold is not 0.500 to 1.000 inclusive")
    high_kev = kev_counts[4]
    high_full = epss_counts[4]
    medium_plus_kev = sum(kev_counts[3:5])
    medium_plus_full = sum(epss_counts[3:5])

    lines = [
        "# Archived KEV and EPSS: a source-pinned cohort comparison",
        "",
        "**Classification:** Empirical aggregate analysis of two archived source snapshots. "
        "Not a live vulnerability feed.",
        "",
        "## Executive reading",
        "",
        f"- **EPSS match coverage of KEV:** {matched:,} of {total_kev:,} KEV CVEs "
        f"({_percentage(matched, total_kev)}). Unmatched KEV: {unmatched:,}.",
        f"- **Highest EPSS interval (0.500 to 1.000 inclusive):** {high_kev:,} of "
        f"{matched:,} scored KEV CVEs ({_percentage(high_kev, matched)}), compared with "
        f"{high_full:,} of {full:,} scored CVEs in the full EPSS population "
        f"({_percentage(high_full, full)}).",
        f"- **EPSS at or above 0.100:** {medium_plus_kev:,} of {matched:,} scored "
        f"KEV CVEs ({_percentage(medium_plus_kev, matched)}) versus "
        f"{medium_plus_full:,} of {full:,} in the full EPSS population "
        f"({_percentage(medium_plus_full, full)}).",
        "",
        "These percentages describe distributions with **different denominators**. "
        "Scored KEV is a subset of the full EPSS population, so the groups are not independent.",
        "",
        "## Five-band distribution",
        "",
        f"| EPSS interval | Full EPSS count (n={full:,}) | Full share | "
        f"Scored KEV count (n={matched:,}) | Scored KEV share |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for band, population_count, kev_count in zip(bands, epss_counts, kev_counts[:5], strict=True):
        label = str(band["band_label"]).replace("|", "\\|").replace("`", "")
        lines.append(
            f"| `{label}` | {population_count:,} | {_percentage(population_count, full)} | "
            f"{kev_count:,} | {_percentage(kev_count, matched)} |"
        )
    lines += [
        "",
        f"**Unscored KEV:** {unmatched:,} of {total_kev:,} "
        f"({_percentage(unmatched, total_kev)} of all KEV). This is not a probability band "
        "and must not be treated as an EPSS score of zero.",
        "",
        "## Source provenance",
        "",
        "| Field | Archived CISA KEV | Archived FIRST EPSS |",
        "| --- | --- | --- |",
        f"| Source date | `{sources['kev']['source_date']}` | "
        f"`{sources['epss']['source_date']}` |",
        f"| Snapshot ID (SHA-256) | `{kev_snapshot}` | `{epss_snapshot}` |",
        f"| Retrieved UTC | `{sources['kev']['retrieved_at_utc']}` | "
        f"`{sources['epss']['retrieved_at_utc']}` |",
        f"| Source row count | {total_kev:,} | {full:,} |",
        f"| EPSS model version | N/A | "
        f"`{sources['epss']['model_version'] or 'not recorded'}` |",
        "",
        f"The verified export uses contract `patchline.analytics-export.v2` with "
        f"{len(manifest['artifacts'])} data artifacts, distributed across JSON, CSV and Parquet. "
        "The full local bundle was verified against recorded digests before this report was generated.",
        "",
        "## Method and limitations",
        "",
        "1. Select one archived KEV catalog and one archived EPSS daily score snapshot. "
        "Validate the source files and retain their exact snapshot IDs and source dates.",
        "2. Join CVEs by identifier using the Patchline DuckDB and dbt pipeline. "
        "M03 records score coverage; M04 records the full scored EPSS population; "
        "M05 records the scored KEV cohort and an explicit unscored KEV category.",
        "3. Compare the same five inclusive/exclusive score intervals with the correct "
        "denominators. No missing scores are imputed, and no score intervals are renamed.",
        "4. EPSS estimates future exploitation probability over a 30-day horizon. "
        "KEV membership indicates known exploitation. Neither measures asset exposure, "
        "impact or a company's remediation priority.",
        "5. These archived snapshots have distinct source timestamps. The comparison is "
        "descriptive and snapshot-specific, not causal, time-series evidence or a claim "
        "about a current vulnerability's exploitability.",
        "",
        "## Reproducibility boundary",
        "",
        "This report was generated from the immutable, locally verified v2 export bundle. "
        "The original data files remain outside Git. The public Spectral Index deployment "
        "uses a separate **synthetic fixture**, not these archived measurements.",
        "",
        "To reproduce, rebuild the warehouse from the pinned snapshot IDs, run "
        "`dbt run` and `dbt test`, create a v2 export, verify the complete export "
        "bundle, then run the report generator with the same explicit IDs.",
        "",
    ]
    report = "\n".join(lines)
    if "\u2014" in report:
        raise ResearchError("Generated research copy contains a prohibited em dash")
    return report


def create_report(
    export: Path, output: Path, *, kev_snapshot: str, epss_snapshot: str,
) -> str:
    """Verify all bundle files before generating an exclusive-write report."""
    if output.exists() or output.is_symlink():
        raise ResearchError("Refusing to overwrite an existing report")
    if not export.is_dir() or export.is_symlink():
        raise ResearchError("Expected an existing local export directory")
    # Import lazily so pure report-rendering tests need no DuckDB connection.
    from patchline.exports.analytics import verify_bundle

    manifest = verify_bundle(export)
    datasets = {model: _rows(export, model, count) for model, count in MODEL_ROWS.items()}
    report = render_report(
        manifest, datasets, kev_snapshot=kev_snapshot, epss_snapshot=epss_snapshot
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    except FileExistsError as exc:
        raise ResearchError("Report appeared during publication; refusing overwrite") from exc
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kev-snapshot", required=True)
    parser.add_argument("--epss-snapshot", required=True)
    args = parser.parse_args(argv)
    try:
        report = create_report(
            args.export, args.output, kev_snapshot=args.kev_snapshot,
            epss_snapshot=args.epss_snapshot,
        )
    except (ResearchError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Research report failed: {exc}", file=sys.stderr)
        return 1
    print(f"Research report created: {args.output} ({len(report)} characters)")
    print("Classification: archived_source_snapshots (review before publication)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
