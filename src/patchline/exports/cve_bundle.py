"""EA-03A4E2: local, write-once CVE consumer bundle with independent verification.

Not a publisher, historical reconstruction, source archive attestation, or live API.
The verifier requires the original external bounded-join JSON as a second input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from patchline.exports.cve_contract import (
    CANDIDATE_STATUS,
    CONTRACT_ID,
    JOIN_ID,
    CVEContractError,
    validate_candidate,
)

BUNDLE_ID = "exploit-atlas.local-cve-bundle.v1"
BUNDLE_STATUS = "local_only_not_approved_for_publication"
CANDIDATE_FILE = "candidate.json"
MANIFEST_FILE = "manifest.json"
MAX_JSON_BYTES = 64 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[3]
_CANDIDATE_FIELDS = (
    "data_kind", "row_scope", "analysis_cutoff_date", "time_precision",
    "selection_contract", "time_coverage_contract", "source_ids", "coverage",
    "records", "historical_as_of_reconstruction_attested",
    "nvd_global_coverage_attested", "organization_asset_exposure_known",
    "source_archive_reverified_by_this_command", "published_to_public_demo",
)
_MANIFEST_FIELDS = frozenset((
    "schema_id", "status", "source_join_schema_id", "candidate_schema_id",
    "source_join_sha256", "files", "nvd_query_id", "row_count", "coverage",
    "public_release_approved",
))
_FILE_FIELDS = frozenset(("path", "sha256", "bytes"))
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")


class CVEBundleError(ValueError):
    """The local bundle is unsafe, incomplete, or unverifiable."""


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise CVEBundleError(message)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(document: object) -> bytes:
    try:
        return (json.dumps(
            document, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ) + "\n").encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CVEBundleError("Document is not finite JSON") from exc


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CVEBundleError(f"Non-finite JSON value: {value}")


def _decode_document(raw: bytes, label: str) -> dict[str, Any]:
    _require(len(raw) <= MAX_JSON_BYTES, f"{label}: JSON exceeds size limit")
    try:
        result = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CVEBundleError(f"{label}: invalid UTF-8 JSON") from exc
    _require(type(result) is dict, f"{label}: JSON root must be an object")
    return result


def _read_file(file: Path, label: str) -> bytes:
    _require(file.is_file() and not file.is_symlink(), f"{label}: missing or symlinked file")
    _require(file.stat().st_size <= MAX_JSON_BYTES, f"{label}: file too large")
    raw = file.read_bytes()
    _require(len(raw) <= MAX_JSON_BYTES, f"{label}: file too large")
    return raw


def _load_source(source_report: Path) -> tuple[dict[str, Any], bytes]:
    _require(source_report.suffix.lower() == ".json", "Source must be a .json file")
    raw = _read_file(source_report, "Source report")
    return _decode_document(raw, "Source report"), raw


def _outside_repo(target: Path) -> None:
    _require(
        not target.resolve().is_relative_to(REPO_ROOT),
        "Local bundle must be outside the Git repository",
    )


def _make_candidate(source: Mapping[str, Any]) -> dict[str, Any]:
    try:
        candidate = {field: deepcopy(source[field]) for field in _CANDIDATE_FIELDS}
    except KeyError as exc:
        raise CVEBundleError(f"Source report missing required field: {exc}") from exc
    candidate.update({
        "schema_id": CONTRACT_ID,
        "status": CANDIDATE_STATUS,
        "source_join_schema_id": JOIN_ID,
    })
    validate_candidate(candidate, bounded_join=source)
    return candidate


def _require_manifest(manifest: dict[str, Any]) -> Mapping[str, Any]:
    _require(set(manifest) == _MANIFEST_FIELDS, "Manifest keys differ from bundle contract")
    _require(manifest["schema_id"] == BUNDLE_ID, "Unexpected bundle schema ID")
    _require(manifest["status"] == BUNDLE_STATUS, "Unexpected bundle status")
    _require(manifest["candidate_schema_id"] == CONTRACT_ID, "Candidate schema ID mismatch")
    _require(manifest["source_join_schema_id"] == JOIN_ID, "Source join schema ID mismatch")
    _require(manifest["public_release_approved"] is False, "Public release claim forbidden")
    _require(
        type(manifest["source_join_sha256"]) is str
        and _HEX_256.fullmatch(manifest["source_join_sha256"]) is not None,
        "Invalid source digest",
    )
    _require(type(manifest["nvd_query_id"]) is str, "Invalid NVD query identity")
    _require(type(manifest["row_count"]) is int and manifest["row_count"] >= 0,
             "Invalid manifest record count")
    _require(type(manifest["coverage"]) is dict, "Invalid manifest coverage")
    files = manifest["files"]
    _require(type(files) is list and len(files) == 1, "Unexpected bundle file inventory")
    entry = files[0]
    _require(type(entry) is dict and set(entry) == _FILE_FIELDS,
             "Invalid bundle file entry")
    _require(entry["path"] == CANDIDATE_FILE, "Unexpected candidate path")
    _require(type(entry["sha256"]) is str and _HEX_256.fullmatch(entry["sha256"]) is not None,
             "Invalid candidate digest")
    _require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= MAX_JSON_BYTES,
             "Invalid candidate byte count")
    return entry


def verify_bundle(*, source_report: Path, bundle_dir: Path) -> dict[str, Any]:
    """Read-only verification against an EXTERNAL, independently supplied source report.

    Verifies bytes and consistency, not trusted authorship of either input.
    """
    source_report = Path(source_report)
    bundle_dir = Path(bundle_dir)
    _require(bundle_dir.is_dir() and not bundle_dir.is_symlink(),
             "Bundle directory is missing or symlinked")
    _outside_repo(bundle_dir)
    _outside_repo(source_report)
    _require(source_report.resolve().parent != bundle_dir.resolve(),
             "Original source report cannot be within the bundle")
    observed = {item.name for item in bundle_dir.iterdir()}
    _require(observed == {MANIFEST_FILE, CANDIDATE_FILE},
             "Bundle has missing or unexpected files")
    manifest_raw = _read_file(bundle_dir / MANIFEST_FILE, "Manifest")
    candidate_raw = _read_file(bundle_dir / CANDIDATE_FILE, "Candidate")
    manifest = _decode_document(manifest_raw, "Manifest")
    candidate = _decode_document(candidate_raw, "Candidate")
    file_record = _require_manifest(manifest)
    source, source_raw = _load_source(source_report)

    _require(_sha(source_raw) == manifest["source_join_sha256"],
             "Original bounded join SHA-256 mismatch")
    _require(len(candidate_raw) == file_record["bytes"], "Candidate byte count mismatch")
    _require(_sha(candidate_raw) == file_record["sha256"], "Candidate SHA-256 mismatch")
    _require(candidate_raw == _canonical_json(candidate),
             "Candidate bytes are not deterministic canonical JSON")
    _require(manifest_raw == _canonical_json(manifest),
             "Manifest bytes are not deterministic canonical JSON")
    try:
        validate_candidate(candidate, bounded_join=source)
    except CVEContractError as exc:
        raise CVEBundleError(f"Consumer/source reconciliation failed: {exc}") from exc
    _require(manifest["coverage"] == candidate["coverage"],
             "Manifest coverage differs from consumer candidate")
    _require(manifest["row_count"] == len(candidate["records"]),
             "Manifest record count differs from consumer candidate")
    _require(manifest["nvd_query_id"] == candidate["source_ids"]["nvd_query_id"],
             "Manifest NVD query identity differs from consumer candidate")
    return {
        "schema_id": BUNDLE_ID,
        "status": "verified_local_bundle_not_published",
        "records_checked": len(candidate["records"]),
        "source_join_sha256": _sha(source_raw),
        "public_release_approved": False,
    }


def create_bundle(*, source_report: Path, output_dir: Path,
                  acknowledge_local_only: bool) -> dict[str, Any]:
    """Write once into a NEW directory; never replace or publish anything."""
    _require(acknowledge_local_only is True,
             "Explicit local-only acknowledgement required")
    source_report = Path(source_report)
    output_dir = Path(output_dir)
    _outside_repo(output_dir)
    _outside_repo(source_report)
    _require(not output_dir.exists() and not output_dir.is_symlink(),
             "Bundle output already exists or is a symlink; no overwrite allowed")
    _require(output_dir.parent.is_dir() and not output_dir.parent.is_symlink(),
             "Bundle output parent must be an existing real directory")
    source, source_raw = _load_source(source_report)
    try:
        candidate = _make_candidate(source)
    except CVEContractError as exc:
        raise CVEBundleError(f"Consumer candidate rejected: {exc}") from exc
    candidate_raw = _canonical_json(candidate)
    _require(len(candidate_raw) <= MAX_JSON_BYTES, "Candidate exceeds size limit")
    manifest = {
        "schema_id": BUNDLE_ID,
        "status": BUNDLE_STATUS,
        "candidate_schema_id": CONTRACT_ID,
        "source_join_schema_id": JOIN_ID,
        "source_join_sha256": _sha(source_raw),
        "files": [{
            "path": CANDIDATE_FILE,
            "sha256": _sha(candidate_raw),
            "bytes": len(candidate_raw),
        }],
        "nvd_query_id": candidate["source_ids"]["nvd_query_id"],
        "row_count": len(candidate["records"]),
        "coverage": deepcopy(candidate["coverage"]),
        "public_release_approved": False,
    }
    manifest_raw = _canonical_json(manifest)
    _require(len(manifest_raw) <= MAX_JSON_BYTES, "Manifest exceeds size limit")

    # Directory and both files are exclusive-create; failures intentionally leave
    # an incomplete directory for inspection, never delete or silently overwrite.
    output_dir.mkdir()
    with (output_dir / CANDIDATE_FILE).open("xb") as handle:
        handle.write(candidate_raw)
    with (output_dir / MANIFEST_FILE).open("xb") as handle:
        handle.write(manifest_raw)
    return verify_bundle(source_report=source_report, bundle_dir=output_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Write a new local-only consumer bundle")
    create.add_argument("--source-report", type=Path, required=True)
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--acknowledge-local-only", action="store_true")
    verify = commands.add_parser("verify", help="Verify a bundle against its original source")
    verify.add_argument("--source-report", type=Path, required=True)
    verify.add_argument("--bundle-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_bundle(
                source_report=args.source_report, output_dir=args.output_dir,
                acknowledge_local_only=args.acknowledge_local_only,
            )
        else:
            result = verify_bundle(
                source_report=args.source_report, bundle_dir=args.bundle_dir,
            )
    except (CVEBundleError, CVEContractError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, sort_keys=True),
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
