# EA-02C3 — Local evidence receipt (slice 2)

This checkpoint takes the existing unapproved aggregate candidate (EA-02C3 slice 1), independently checks the original **local** archived analytics v2 export and rederives the exact insight bytes with the already-shipped Python verifier, and writes a **metadata-only** receipt into the operating system temporary directory.

## Verification boundary

- `patchline.exports.analytics.verify_bundle` validates the local v2 export manifest, all twelve CSV/JSON/Parquet artifact bytes and the exported model contract.
- `patchline.research.insights.verify_insight_pack` rederives the archived insight file from that same verified bundle and pinned KEV/EPSS source snapshot IDs; it refuses differing insight bytes.
- `patchline.research.evidence_receipt` independently compares the browser candidate fingerprint against those verified bytes, confirms its source identities and ensures all publication flags remain unapproved.
- Receipt records `export_artifacts_verified: true`, `insight_bytes_independently_rederived: true` and `upstream_feed_authenticity_independently_proven: false`. The last flag matters: validating a local archive and checksums does not prove that the original upstream sites were authentic at acquisition time.

No source data or full analytical findings are copied into the receipt. It records checksums, source snapshot IDs, timestamps, population sizes, and insight IDs only. A local receipt is **not** publication approval, and it is not accepted by the GitHub Pages build.

## Example (Windows PowerShell 5.1)

Run from the repository root after syncing `main`. Keep the original 2026 insight JSON outside Git. To create a fresh candidate manifest:

```powershell
$repo = Join-Path $HOME 'Projects\patchline'
$insights = Join-Path $HOME 'Downloads\ea02c2-archived-insights-2026-11-11.json'
$export = Join-Path $repo 'data\exports\p6a-real-2026-11-11-v2'
Set-Location $repo
$candidateResult = node apps/web/scripts/research-publication-candidate.mjs --input $insights | ConvertFrom-Json
uv run --locked python -m patchline.research.evidence_receipt `
  --export $export `
  --insights $insights `
  --candidate $candidateResult.output
```

The CLI fails closed if any export artifact, rederived insight, snapshot ID, digest, count, or safety flag fails verification. The output receipt is outside the repository in Windows TEMP.

## Tests

```powershell
uv run --locked pytest -q tests/test_research_evidence_receipt.py
uv run --locked pytest -q
uv run --locked ruff check .
```

Contract unit tests use **invented** 2099 source identities. Integration with actual historical source bytes is run locally using the command above, not in CI, and the real research is never committed.

## Deliberately not implemented here

No upload, public payload, approval record, GitHub Pages wiring, download of live feeds, change to the synthetic public Explorer, or upstream authenticity attestation. Any historical public aggregate release requires its own reviewed contract, explicit permission and review of dated claims.
