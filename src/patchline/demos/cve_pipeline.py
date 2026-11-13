"""EA-03A4E3: reproducible local synthetic CVE join-to-bundle demonstration.

Executes existing bounded join, consumer contract, write-once exporter and verifier.
Not a live source ingestion, DuckDB source attestation, or public publisher.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from patchline.exports.cve_bundle import create_bundle, verify_bundle
from patchline.fixtures.cve_pipeline import CUTOFF, synthetic_selection_and_rows
from patchline.warehouse.cross_source_join import build_bounded_join, save_local_no_replace

DEMO_ID = "exploit-atlas.synthetic-cve-pipeline-demo.v1"
RUNS = ("run-a", "run-b")
SOURCE_FILE = "bounded-join.json"
EVIDENCE_FILE = "evidence.json"
REPO_ROOT = Path(__file__).resolve().parents[3]


class CVEPipelineDemoError(ValueError):
    """The synthetic demonstration was unsafe or failed verification."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CVEPipelineDemoError(message)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _report_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2,
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _outside_git_tree(path: Path) -> None:
    resolved = path.resolve()
    _require(not resolved.is_relative_to(REPO_ROOT),
             "Demo output cannot be placed inside the source repository")
    _require(not any((parent / ".git").exists() for parent in (resolved, *resolved.parents)),
             "Demo output cannot be placed in any Git working tree")


def _fixture_report() -> dict[str, Any]:
    selected, rows = synthetic_selection_and_rows()
    return build_bounded_join(
        selected,
        cutoff_date=CUTOFF,
        acknowledge_bounded_nvd=True,
        **rows,
    )


def _inspect(directory: Path) -> dict[str, Any]:
    """Independently derive and verify evidence using actual E1/E2 checks."""
    directory = Path(directory)
    _outside_git_tree(directory)
    _require(directory.is_dir() and not directory.is_symlink(),
             "Demo directory is missing or is a symlink")
    _require({p.name for p in directory.iterdir()} == {*RUNS, EVIDENCE_FILE},
             "Demo directory must contain exactly two runs and evidence.json")

    source_expected = _report_bytes(_fixture_report())
    recorded: list[dict[str, Any]] = []
    run_bytes: list[tuple[bytes, bytes, bytes]] = []
    for run_id in RUNS:
        run = directory / run_id
        _require(run.is_dir() and not run.is_symlink(), "Missing or symlinked run directory")
        _require({p.name for p in run.iterdir()} == {SOURCE_FILE, "bundle"},
                 "Unexpected files in demo run")
        source = run / SOURCE_FILE
        _require(source.is_file() and not source.is_symlink(),
                 "Source report must be a regular file")
        raw = source.read_bytes()
        _require(raw == source_expected,
                 "Synthetic bounded join differs from independently rebuilt fixture")
        bundle_dir = run / "bundle"
        result = verify_bundle(source_report=source, bundle_dir=bundle_dir)
        _require(result["records_checked"] == 3 and result["public_release_approved"] is False,
                 "Unexpected CVE count or unsupported public-release claim")
        candidate = (bundle_dir / "candidate.json").read_bytes()
        manifest = (bundle_dir / "manifest.json").read_bytes()
        run_bytes.append((raw, candidate, manifest))
        recorded.append({
            "run": run_id,
            "source_join_sha256": _sha(raw),
            "candidate_sha256": _sha(candidate),
            "manifest_sha256": _sha(manifest),
            "verified_cve_records": result["records_checked"],
        })
    _require(run_bytes[0] == run_bytes[1],
             "Repeated synthetic runs produced different artifact bytes")

    join = _fixture_report()
    evidence = {
        "schema_id": DEMO_ID,
        "status": "verified_offline_synthetic_demonstration",
        "data_kind": "synthetic_fixture",
        "input_scope": "in_memory_synthetic_selected_rows_not_source_archive_attestation",
        "analysis_cutoff_date": CUTOFF,
        "coverage": join["coverage"],
        "runs": recorded,
        "byte_identical_repeats": True,
        "original_source_archives_reverified": False,
        "public_release_approved": False,
        "public_site_modified": False,
    }
    evidence_file = directory / EVIDENCE_FILE
    _require(evidence_file.is_file() and not evidence_file.is_symlink(),
             "Missing or symlinked evidence.json")
    _require(evidence_file.read_bytes() == _canonical(evidence),
             "Evidence document does not reconcile to independently verified artifacts")
    return evidence


def create_demonstration(*, output_dir: Path,
                         acknowledge_synthetic_only: bool) -> dict[str, Any]:
    """Create two fresh locally verified runs; never overwrite or publish."""
    _require(acknowledge_synthetic_only is True,
             "Explicit --acknowledge-synthetic-only flag is required")
    output_dir = Path(output_dir).absolute()
    _outside_git_tree(output_dir)
    _require(not output_dir.exists() and not output_dir.is_symlink(),
             "Output already exists or is a symlink; refusing overwrite")
    _require(output_dir.parent.is_dir() and not output_dir.parent.is_symlink(),
             "Output parent must be an existing real directory")

    report = _fixture_report()
    _require(report["coverage"]["nvd_query_cves"] == 3,
             "Unexpected synthetic NVD query size")
    output_dir.mkdir()
    for run_id in RUNS:
        run_dir = output_dir / run_id
        run_dir.mkdir()
        source = run_dir / SOURCE_FILE
        save_local_no_replace(report, output=source, forbidden_inputs=())
        create_bundle(
            source_report=source, output_dir=run_dir / "bundle",
            acknowledge_local_only=True,
        )

    # Build evidence from checked artifacts, not from guessed counts.
    # _inspect requires the evidence file: produce it from its exact expected structure.
    raw = (output_dir / RUNS[0] / SOURCE_FILE).read_bytes()
    candidate = (output_dir / RUNS[0] / "bundle" / "candidate.json").read_bytes()
    manifest = (output_dir / RUNS[0] / "bundle" / "manifest.json").read_bytes()
    recorded = [
        {
            "run": run_id,
            "source_join_sha256": _sha(raw),
            "candidate_sha256": _sha(candidate),
            "manifest_sha256": _sha(manifest),
            "verified_cve_records": 3,
        }
        for run_id in RUNS
    ]
    evidence = {
        "schema_id": DEMO_ID,
        "status": "verified_offline_synthetic_demonstration",
        "data_kind": "synthetic_fixture",
        "input_scope": "in_memory_synthetic_selected_rows_not_source_archive_attestation",
        "analysis_cutoff_date": CUTOFF,
        "coverage": report["coverage"],
        "runs": recorded,
        "byte_identical_repeats": True,
        "original_source_archives_reverified": False,
        "public_release_approved": False,
        "public_site_modified": False,
    }
    with (output_dir / EVIDENCE_FILE).open("xb") as handle:
        handle.write(_canonical(evidence))
    return verify_demonstration(demo_dir=output_dir)


def verify_demonstration(*, demo_dir: Path) -> dict[str, Any]:
    """Read-only full verification; recomputes the fixture and every recorded digest."""
    return _inspect(Path(demo_dir))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Create a new local synthetic demonstration")
    create.add_argument("--output-dir", required=True, type=Path)
    create.add_argument("--acknowledge-synthetic-only", action="store_true")
    verify = commands.add_parser("verify", help="Verify an existing demo without writing")
    verify.add_argument("--demo-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_demonstration(
                output_dir=args.output_dir,
                acknowledge_synthetic_only=args.acknowledge_synthetic_only,
            )
        else:
            result = verify_demonstration(demo_dir=args.demo_dir)
    except (CVEPipelineDemoError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, sort_keys=True),
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
