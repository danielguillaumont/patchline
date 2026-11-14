"""EA-02C3 evidence-receipt contract tests: invented metadata only."""
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

from patchline.research.evidence_receipt import (
    INSIGHT_IDS,
    REVIEW_REQUIREMENTS,
    EvidenceReceiptError,
    _strict_json,
    validate_candidate,
    verify_and_write_receipt,
)


def _bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _case():
    sources = [
        {"source": "kev", "snapshot_id": "a" * 64,
         "source_date": "2099-01-10T00:00:00Z", "row_count": 3},
        {"source": "epss", "snapshot_id": "b" * 64,
         "source_date": "2099-01-11T00:00:00Z", "row_count": 4},
    ]
    pack = {
        "schema_id": "exploit-atlas.archived-insights.v1",
        "data_kind": "archived_source_snapshots",
        "publication_scope": "local_review_only",
        "public_release_approved": False,
        "source_snapshots": sources,
        "insights": [{"id": name} for name in list(INSIGHT_IDS)],
    }
    raw = _bytes(pack)
    candidate = {
        "schema_id": "exploit-atlas.archived-aggregate-publication-candidate.v1",
        "candidate_status": "local_review_candidate_only",
        "data_kind": "archived_source_snapshots",
        "public_release_approved": False,
        "publication_scope": "not_for_publication",
        "browser_contract_validated": True,
        "source_archives_reverified_by_this_tool": False,
        "source_archive_verification_required": True,
        "candidate_contains_research_data": False,
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "input_byte_count": len(raw),
        "source_snapshots": sources,
        "insight_ids": list(INSIGHT_IDS),
        "review_requirements": list(REVIEW_REQUIREMENTS),
    }
    export_manifest = {
        "schema_id": "patchline.analytics-export.v2",
        "data_kind": "archived_source_snapshots",
        "source_snapshots": list(reversed(sources)),
        "artifacts": [{"path": f"synthetic-{n}"} for n in range(12)],
    }
    return raw, candidate, export_manifest


def test_accepts_exact_metadata_candidate_but_never_approves_publication():
    insight, candidate, export = _case()
    assert validate_candidate(_bytes(candidate), insight, export)["public_release_approved"] is False


def test_rejects_reformatted_or_changed_insight_bytes():
    insight, candidate, export = _case()
    altered = json.dumps(json.loads(insight), indent=2).encode()
    with pytest.raises(EvidenceReceiptError, match="exact insight bytes"):
        validate_candidate(_bytes(candidate), altered, export)


@pytest.mark.parametrize("field,value", [
    ("public_release_approved", True),
    ("publication_scope", "public"),
    ("source_archives_reverified_by_this_tool", True),
    ("candidate_contains_research_data", True),
    ("browser_contract_validated", False),
])
def test_rejects_forged_candidate_safety_claims(field, value):
    insight, candidate, export = _case()
    candidate[field] = value
    with pytest.raises(EvidenceReceiptError, match="safety fields"):
        validate_candidate(_bytes(candidate), insight, export)


def test_rejects_unknown_candidate_field():
    insight, candidate, export = _case()
    candidate["risk_score"] = 99
    with pytest.raises(EvidenceReceiptError, match="unexpected fields"):
        validate_candidate(_bytes(candidate), insight, export)


def test_rejects_unknown_finding_id():
    insight, candidate, export = _case()
    candidate["insight_ids"][0] = "fabricated"
    with pytest.raises(EvidenceReceiptError, match="identities differ"):
        validate_candidate(_bytes(candidate), insight, export)


def test_rejects_different_source_pair():
    insight, candidate, export = _case()
    export["source_snapshots"][0] = {
        **export["source_snapshots"][0], "snapshot_id": "c" * 64,
    }
    with pytest.raises(EvidenceReceiptError, match="differs in snapshot_id"):
        validate_candidate(_bytes(candidate), insight, export)


def test_rejects_synthetic_export_and_incomplete_bundle():
    insight, candidate, export = _case()
    export["data_kind"] = "synthetic_fixture"
    with pytest.raises(EvidenceReceiptError, match="archived v2 export"):
        validate_candidate(_bytes(candidate), insight, export)
    export["data_kind"] = "archived_source_snapshots"
    export["artifacts"].pop()
    with pytest.raises(EvidenceReceiptError, match="12 artifacts"):
        validate_candidate(_bytes(candidate), insight, export)


def test_rejects_changed_review_requirements():
    insight, candidate, export = _case()
    candidate["review_requirements"][2] = "Automatically publish"
    with pytest.raises(EvidenceReceiptError, match="safety fields"):
        validate_candidate(_bytes(candidate), insight, export)


def test_strict_json_rejects_duplicate_fields_and_nonfinite_numbers():
    with pytest.raises(EvidenceReceiptError, match="Duplicate JSON key"):
        _strict_json(b'{"approved":false,"approved":true}')
    with pytest.raises(EvidenceReceiptError, match="Invalid JSON number"):
        _strict_json(b'{"value":NaN}')


def test_integration_receipt_is_written_only_after_both_verifiers(tmp_path, monkeypatch):
    insight_bytes, candidate, manifest = _case()
    export = tmp_path / "archive"
    export.mkdir()
    (export / "manifest.json").write_bytes(_bytes(manifest))
    insight_file = tmp_path / "insights.json"
    candidate_file = tmp_path / "candidate.json"
    insight_file.write_bytes(insight_bytes)
    candidate_file.write_bytes(_bytes(candidate))
    calls = []

    export_mod = types.ModuleType("patchline.exports.analytics")
    def checked_export(p):
        assert Path(p) == export
        calls.append("export")
        return manifest
    export_mod.verify_bundle = checked_export

    insight_mod = types.ModuleType("patchline.research.insights")
    def checked_insight(p, output, *, kev_snapshot, epss_snapshot):
        assert Path(p) == export
        assert Path(output) == insight_file
        assert (kev_snapshot, epss_snapshot) == ("a" * 64, "b" * 64)
        calls.append("insights")
    insight_mod.verify_insight_pack = checked_insight
    monkeypatch.setitem(sys.modules, "patchline.exports.analytics", export_mod)
    monkeypatch.setitem(sys.modules, "patchline.research.insights", insight_mod)

    receipt_path = verify_and_write_receipt(export, insight_file, candidate_file)
    receipt = json.loads(receipt_path.read_bytes())
    assert calls == ["export", "insights"]
    assert receipt["export_artifacts_verified"] is True
    assert receipt["insight_bytes_independently_rederived"] is True
    assert receipt["upstream_feed_authenticity_independently_proven"] is False
    assert receipt["public_release_approved"] is False
    assert "insights" not in receipt  # No original explanatory research in the receipt.
    receipt_path.unlink()
    receipt_path.parent.rmdir()


def test_failed_export_verification_does_not_produce_receipt(tmp_path, monkeypatch):
    insight_bytes, candidate, manifest = _case()
    export = tmp_path / "archive"
    export.mkdir()
    (export / "manifest.json").write_bytes(_bytes(manifest))
    insight_file = tmp_path / "insights.json"
    candidate_file = tmp_path / "candidate.json"
    insight_file.write_bytes(insight_bytes)
    candidate_file.write_bytes(_bytes(candidate))

    export_mod = types.ModuleType("patchline.exports.analytics")
    def failed_export(_):
        raise ValueError("Altered source artifact")
    export_mod.verify_bundle = failed_export
    insight_mod = types.ModuleType("patchline.research.insights")
    def should_not_run(*args, **kwargs):
        raise AssertionError("Insight verification must not run after export failure")
    insight_mod.verify_insight_pack = should_not_run
    monkeypatch.setitem(sys.modules, "patchline.exports.analytics", export_mod)
    monkeypatch.setitem(sys.modules, "patchline.research.insights", insight_mod)

    with pytest.raises(ValueError, match="Altered source artifact"):
        verify_and_write_receipt(export, insight_file, candidate_file)
