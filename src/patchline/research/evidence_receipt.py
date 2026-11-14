"""EA-02C3 Slice 2: local, non-publishing evidence verification receipt.

Verifies an immutable archived v2 export and independently rederives the exact
insight bytes before writing a metadata-only receipt outside the repository.
This does not authenticate the upstream feeds or authorize publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "exploit-atlas.archived-evidence-verification-receipt.v1"
CANDIDATE_SCHEMA = "exploit-atlas.archived-aggregate-publication-candidate.v1"
INSIGHT_SCHEMA = "exploit-atlas.archived-insights.v1"
MAX_JSON_BYTES = 65536
MAX_MANIFEST_BYTES = 524288
CANDIDATE_KEYS = {
    "schema_id", "candidate_status", "data_kind", "public_release_approved",
    "publication_scope", "browser_contract_validated",
    "source_archives_reverified_by_this_tool", "source_archive_verification_required",
    "candidate_contains_research_data", "input_sha256", "input_byte_count",
    "source_snapshots", "insight_ids", "review_requirements",
}
INSIGHT_IDS = ["highest-epss-band", "epss-coverage", "epss-at-least-point-one"]
REVIEW_REQUIREMENTS = [
    "Independently verify the original 12-artifact v2 source export and insight JSON with the Python CLI.",
    "Review all three aggregate interpretations, denominators, caveats, and exact pinned input bytes.",
    "Obtain a separate explicit human approval before any public publication.",
]


class EvidenceReceiptError(ValueError):
    """A required verification condition was not met."""


def _reject(message: str) -> None:
    raise EvidenceReceiptError(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(data: bytes) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                _reject(f"Duplicate JSON key: {key}")
            obj[key] = value
        return obj

    def no_constant(value: str) -> None:
        _reject(f"Invalid JSON number: {value}")

    try:
        return json.loads(data.decode("utf-8", errors="strict"),
                          object_pairs_hook=no_duplicates, parse_constant=no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceReceiptError("Invalid UTF-8 JSON") from exc


def _file(path: Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        _reject("Expected an absolute, existing non-symlink JSON file")
    if path.stat().st_size == 0 or path.stat().st_size > maximum:
        _reject("JSON file size outside permitted bounds")
    return path.read_bytes()


def _source_metadata(pack: dict[str, Any]) -> list[dict[str, Any]]:
    sources = pack.get("source_snapshots")
    if not isinstance(sources, list) or [s.get("source") for s in sources if isinstance(s, dict)] != ["kev", "epss"]:
        _reject("Expected ordered KEV/EPSS source pair")
    keys = {"source", "snapshot_id", "source_date", "row_count"}
    for entry in sources:
        if not isinstance(entry, dict) or set(entry) != keys:
            _reject("Unexpected insight source metadata")
        if not isinstance(entry["snapshot_id"], str) or len(entry["snapshot_id"]) != 64:
            _reject("Invalid snapshot identity")
        if type(entry["row_count"]) is not int or entry["row_count"] < 1:
            _reject("Invalid source population")
    return sources


def validate_candidate(candidate_bytes: bytes, insight_bytes: bytes,
                       export_manifest: dict[str, Any]) -> dict[str, Any]:
    """Check the candidate against byte-exact insight input and verified v2 manifest."""
    candidate = _strict_json(candidate_bytes)
    pack = _strict_json(insight_bytes)
    if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_KEYS:
        _reject("Candidate has missing or unexpected fields")
    if not isinstance(pack, dict) or pack.get("schema_id") != INSIGHT_SCHEMA:
        _reject("Unexpected insight contract")
    sources = _source_metadata(pack)
    if (candidate["schema_id"] != CANDIDATE_SCHEMA or
            candidate["candidate_status"] != "local_review_candidate_only" or
            candidate["data_kind"] != "archived_source_snapshots" or
            candidate["publication_scope"] != "not_for_publication" or
            candidate["public_release_approved"] is not False or
            candidate["browser_contract_validated"] is not True or
            candidate["source_archives_reverified_by_this_tool"] is not False or
            candidate["source_archive_verification_required"] is not True or
            candidate["candidate_contains_research_data"] is not False or
            candidate["review_requirements"] != REVIEW_REQUIREMENTS):
        _reject("Candidate provenance or publication safety fields changed")
    if (candidate["input_sha256"] != _sha256(insight_bytes) or
            type(candidate["input_byte_count"]) is not int or
            candidate["input_byte_count"] != len(insight_bytes)):
        _reject("Candidate does not match the exact insight bytes")
    insights = pack.get("insights")
    if not isinstance(insights, list) or [i.get("id") for i in insights if isinstance(i, dict)] != INSIGHT_IDS:
        _reject("Unexpected insight identifiers")
    if (candidate["source_snapshots"] != sources or candidate["insight_ids"] != INSIGHT_IDS):
        _reject("Candidate source or insight identities differ")
    if (pack.get("data_kind") != "archived_source_snapshots" or
            pack.get("publication_scope") != "local_review_only" or
            pack.get("public_release_approved") is not False):
        _reject("Insight publication status changed")
    if (not isinstance(export_manifest, dict) or
            export_manifest.get("schema_id") != "patchline.analytics-export.v2" or
            export_manifest.get("data_kind") != "archived_source_snapshots" or
            not isinstance(export_manifest.get("artifacts"), list) or
            len(export_manifest["artifacts"]) != 12):
        _reject("Expected verified archived v2 export with 12 artifacts")
    export_sources = export_manifest.get("source_snapshots")
    if not isinstance(export_sources, list) or len(export_sources) != 2:
        _reject("Export is missing its source pair")
    by_source = {s.get("source"): s for s in export_sources if isinstance(s, dict)}
    if set(by_source) != {"kev", "epss"}:
        _reject("Unexpected export source pair")
    for src in sources:
        row = by_source[src["source"]]
        for field in ("snapshot_id", "source_date", "row_count"):
            if row.get(field) != src[field]:
                _reject(f"Source {src['source']} differs in {field}")
    return candidate


def verify_and_write_receipt(export: Path, insights: Path, candidate: Path) -> Path:
    """Verify all export files and rederive insight bytes; emit metadata only to TEMP."""
    if not export.is_absolute() or export.is_symlink() or not export.is_dir():
        _reject("Expected absolute, non-symlink archived export directory")
    root = Path(__file__).resolve().parents[3]
    for path in (insights, candidate):
        actual = path.resolve(strict=True)
        if actual == root or root in actual.parents:
            _reject("Insight and candidate files must remain outside Git repository")
    insight_bytes = _file(insights)
    candidate_bytes = _file(candidate)

    # Only the existing verified implementation is allowed to establish these flags.
    from patchline.exports.analytics import verify_bundle
    from patchline.research.insights import verify_insight_pack

    manifest = verify_bundle(export)
    checked = validate_candidate(candidate_bytes, insight_bytes, manifest)
    sources = checked["source_snapshots"]
    verify_insight_pack(export, insights,
                        kev_snapshot=sources[0]["snapshot_id"],
                        epss_snapshot=sources[1]["snapshot_id"])
    # Fail closed if either local input changed while the source verifier ran.
    if _file(insights) != insight_bytes or _file(candidate) != candidate_bytes:
        _reject("Candidate or insight bytes changed during verification")
    manifest_bytes = _file(export / "manifest.json", MAX_MANIFEST_BYTES)
    if _strict_json(manifest_bytes) != manifest:
        _reject("Export manifest changed during verification")
    receipt = {
        "schema_id": RECEIPT_SCHEMA,
        "status": "verified_local_evidence_only",
        "data_kind": "archived_source_snapshots",
        "publication_scope": "offline_review_only",
        "public_release_approved": False,
        "export_artifacts_verified": True,
        "insight_bytes_independently_rederived": True,
        "upstream_feed_authenticity_independently_proven": False,
        "candidate_sha256": _sha256(candidate_bytes),
        "insight_sha256": _sha256(insight_bytes),
        "export_manifest_sha256": _sha256(manifest_bytes),
        "source_snapshots": sources,
        "insight_ids": INSIGHT_IDS,
    }
    temp_root = Path(tempfile.gettempdir()).resolve()
    if temp_root == root or root in temp_root.parents:
        _reject("Temporary receipt output cannot be within repository")
    output_dir = Path(tempfile.mkdtemp(prefix="exploit-atlas-ea02c3-evidence-", dir=temp_root))
    receipt_path = output_dir / "evidence-receipt.json"
    receipt_path.write_bytes((json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    return receipt_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--insights", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        out = verify_and_write_receipt(args.export, args.insights, args.candidate)
        print(json.dumps({"status": "verified_local_evidence_only", "receipt": str(out),
                          "public_release_approved": False}, sort_keys=True))
    except (EvidenceReceiptError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"EA-02C3 evidence verification rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
