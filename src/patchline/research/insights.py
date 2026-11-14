"""Local-only, source-pinned plain-language insights from a verified archived v2 export.

This module never fetches a network source or authorizes public publication.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from patchline.research.case_study import (
    MODEL_ROWS,
    ResearchError,
    _check_source_pair,
    _rows,
    render_report,
)

SCHEMA_ID = "exploit-atlas.archived-insights.v1"


def _metric(label: str, numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "label": label,
        "count": numerator,
        "population": denominator,
        "share_percent": f"{numerator * 100 / denominator:.2f}",
    }


def _comparison_headline(
    kev_count: int, kev_total: int, full_count: int, full_total: int,
    *, label: str,
) -> str:
    left = kev_count * full_total
    right = full_count * kev_total
    if left > right:
        return f"A larger share of the scored KEV cohort falls in {label}."
    if left < right:
        return f"A smaller share of the scored KEV cohort falls in {label}."
    return f"The two populations have equal shares in {label}."


def build_insight_pack(
    manifest: dict[str, Any],
    datasets: dict[str, list[dict[str, Any]]],
    *,
    kev_snapshot: str,
    epss_snapshot: str,
) -> dict[str, Any]:
    """Build three descriptive findings; first reuse all research-report reconciliation guards."""
    render_report(
        manifest, datasets, kev_snapshot=kev_snapshot, epss_snapshot=epss_snapshot
    )
    sources = _check_source_pair(manifest, kev_snapshot, epss_snapshot)
    coverage = datasets["m03_epss_coverage_of_kev"][0]
    population = datasets["m04_epss_population_summary"][0]
    epss_bands = datasets["m04_epss_score_bands"]
    kev_bands = datasets["m05_kev_epss_cohort_bands"]

    kev_total = coverage["denominator_total_kev"]
    kev_scored = coverage["numerator_matched_kev"]
    full_scored = population["scored_cve_count"]
    highest_kev = kev_bands[4]["kev_cve_count"]
    highest_full = epss_bands[4]["cve_count"]
    above_kev = sum(row["kev_cve_count"] for row in kev_bands[3:5])
    above_full = sum(row["cve_count"] for row in epss_bands[3:5])

    highest_kev_share = _metric("Scored KEV", highest_kev, kev_scored)
    highest_full_share = _metric("Full scored EPSS", highest_full, full_scored)
    above_kev_share = _metric("Scored KEV", above_kev, kev_scored)
    above_full_share = _metric("Full scored EPSS", above_full, full_scored)
    coverage_metric = _metric("KEV records with EPSS", kev_scored, kev_total)

    return {
        "schema_id": SCHEMA_ID,
        "data_kind": "archived_source_snapshots",
        "public_release_approved": False,
        "publication_scope": "local_review_only",
        "method": "verified_v2_m03_m04_m05_descriptive_comparison",
        "source_snapshots": [
            {
                "source": name,
                "snapshot_id": sources[name]["snapshot_id"],
                "source_date": sources[name]["source_date"],
                "row_count": sources[name]["row_count"],
            }
            for name in ("kev", "epss")
        ],
        "population_relation": "scored_kev_is_subset_of_full_scored_epss",
        "insights": [
            {
                "id": "highest-epss-band",
                "headline": _comparison_headline(
                    highest_kev, kev_scored, highest_full, full_scored,
                    label="the highest EPSS band",
                ),
                "plain_language": (
                    f"In this archived source pair, {highest_kev_share['share_percent']}% of "
                    "KEV-listed vulnerabilities with an EPSS score were in the highest band, "
                    f"compared with {highest_full_share['share_percent']}% of all scored vulnerabilities."
                ),
                "why_it_matters": (
                    "KEV records evidence of known exploitation. EPSS estimates future "
                    "exploitation probability. Examining both reveals different aspects of "
                    "the vulnerability landscape."
                ),
                "next_question": (
                    "Which affected products are relevant, and what do their vendors recommend?"
                ),
                "caveat": (
                    "Historical descriptive comparison, not an attack forecast or an "
                    "organization-specific risk estimate. The two groups overlap."
                ),
                "threshold": "EPSS 0.500 to 1.000 inclusive",
                "measures": [highest_kev_share, highest_full_share],
            },
            {
                "id": "epss-coverage",
                "headline": (
                    "All KEV records in this source pair have an EPSS score."
                    if kev_scored == kev_total else
                    "Some KEV records in this source pair do not have an EPSS score."
                ),
                "plain_language": (
                    f"{kev_scored:,} of {kev_total:,} KEV records in these specific "
                    f"archived snapshots had an EPSS match ({coverage_metric['share_percent']}%)."
                ),
                "why_it_matters": (
                    "Coverage tells us how much of one dataset can be compared with "
                    "another. It does not measure whether a vulnerability was exploited."
                ),
                "next_question": (
                    "Would this coverage change with a different snapshot date or source version?"
                ),
                "caveat": (
                    "Snapshot-specific matching coverage is not a guarantee of future "
                    "source completeness or a security outcome."
                ),
                "measures": [coverage_metric],
                "unmatched_kev_count": coverage["unmatched_kev"],
            },
            {
                "id": "epss-at-least-point-one",
                "headline": _comparison_headline(
                    above_kev, kev_scored, above_full, full_scored,
                    label="the EPSS intervals at or above 0.100",
                ),
                "plain_language": (
                    f"{above_kev_share['share_percent']}% of scored KEV records had "
                    "an EPSS value of at least 0.100, versus "
                    f"{above_full_share['share_percent']}% of the full scored EPSS population."
                ),
                "why_it_matters": (
                    "Comparing the same threshold across the two populations helps "
                    "explain the distribution, without treating severity as probability."
                ),
                "next_question": (
                    "How does the result change across the five EPSS intervals?"
                ),
                "caveat": (
                    "The groups have different denominators and overlap. This is not "
                    "a causal comparison or remediation-priority score."
                ),
                "threshold": "EPSS >= 0.100",
                "measures": [above_kev_share, above_full_share],
            },
        ],
        "global_limitation": (
            "No live data, asset inventory, exposure assessment, attribution, "
            "or organizational remediation recommendation is present."
        ),
    }


def _expected_bytes(
    export: Path, *, kev_snapshot: str, epss_snapshot: str
) -> bytes:
    # The verifier validates every file in the original export bundle before use.
    from patchline.exports.analytics import verify_bundle

    manifest = verify_bundle(export)
    datasets = {
        model: _rows(export, model, count) for model, count in MODEL_ROWS.items()
    }
    pack = build_insight_pack(
        manifest, datasets, kev_snapshot=kev_snapshot, epss_snapshot=epss_snapshot
    )
    return (
        json.dumps(pack, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _check_paths(export: Path, output: Path) -> None:
    if not export.is_absolute() or not export.is_dir() or export.is_symlink():
        raise ResearchError("Expected an absolute, existing non-symlink local export directory")
    if not output.is_absolute():
        raise ResearchError("Output path must be absolute")
    repository = Path(__file__).resolve().parents[3]
    resolved = output.resolve(strict=False)
    if resolved == repository or repository in resolved.parents:
        raise ResearchError("Insight output inside repository prohibited")
    if output.is_symlink():
        raise ResearchError("Refusing an output symlink")


def create_insight_pack(
    export: Path, output: Path, *, kev_snapshot: str, epss_snapshot: str
) -> bytes:
    """Verify archived export and exclusively write a review-only insight pack."""
    _check_paths(export, output)
    if output.exists():
        raise ResearchError("Refusing to overwrite an existing insight pack")
    content = _expected_bytes(export, kev_snapshot=kev_snapshot, epss_snapshot=epss_snapshot)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(content)
    return content


def verify_insight_pack(
    export: Path, output: Path, *, kev_snapshot: str, epss_snapshot: str
) -> None:
    """Read-only byte verification against rederived, pinned evidence."""
    _check_paths(export, output)
    if not output.is_file():
        raise ResearchError("Expected an existing insight pack file")
    expected = _expected_bytes(export, kev_snapshot=kev_snapshot, epss_snapshot=epss_snapshot)
    if output.read_bytes() != expected:
        raise ResearchError("Insight pack differs from verified source-pinned derivation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("create", "verify"))
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kev-snapshot", required=True)
    parser.add_argument("--epss-snapshot", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "create":
            create_insight_pack(
                args.export, args.output,
                kev_snapshot=args.kev_snapshot, epss_snapshot=args.epss_snapshot,
            )
            print("EA02C1 local archived insights created - public release NOT approved")
        else:
            verify_insight_pack(
                args.export, args.output,
                kev_snapshot=args.kev_snapshot, epss_snapshot=args.epss_snapshot,
            )
            print("EA02C1 local archived insights independently rederived and verified")
    except (ResearchError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"EA02C1 rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
