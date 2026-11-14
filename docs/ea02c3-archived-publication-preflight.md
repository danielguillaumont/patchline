# EA-02C3 — Historical aggregate publication contract (slice 3)

EA-02C3 Slice 3 adds an **offline, metadata-only preflight contract** connecting the three existing local artifacts: (1) the exact archived insight JSON, (2) the byte-pinned candidate manifest, and (3) the local Python evidence receipt. This is a **review checkpoint, not public approval**.

## What it checks

- Reuses `verifyAggregateCandidate` and the Research Desk validation contract to ensure the exact archived insight bytes match the candidate and retain fixed scope, source identity, three insight IDs, counts, and caveats.
- Requires canonical candidate and receipt JSON bytes to reject changed formatting or duplicate-key ambiguity.
- Checks the receipt's SHA-256 bindings to the exact insight and candidate files, manifest SHA-256 syntax, source dates and source snapshot identities.
- Requires the receipt to record successful **previous local** artifact verification and independent insight rederivation, while retaining `upstream_feed_authenticity_independently_proven: false` and `public_release_approved: false`.
- Emits only metadata: hashes, source IDs/dates/populations, insight identifiers, explicit unapproved status. Never writes the historical insight prose, chart measures, KEV/EPSS rows, public assets, or deployable payloads.

**Important trust boundary:** The Node preflight checks whether the receipt and candidate are mutually consistent. It does **not** independently rerun the Python source verifiers, authenticate how the receipt was generated, or prove upstream feed authenticity. For real data, re-run the Python CLI and use its freshly emitted receipt in the same local workflow. A standalone JSON receipt is not a signed attestation.

## Local command (Windows PowerShell 5.1)

From repo root on the EA-02C3 slice 3 branch, after re-running the Python receipt CLI with verified exports:

```powershell
$repo = Join-Path $HOME 'Projects\patchline'
$insights = Join-Path $HOME 'Downloads\ea02c2-archived-insights-2026-11-11.json'
$export = Join-Path $repo 'data\exports\p6a-real-2026-11-11-v2'
Set-Location $repo
$candidate = (node apps/web/scripts/research-publication-candidate.mjs --input $insights | ConvertFrom-Json)
$receipt = (uv run --locked python -m patchline.research.evidence_receipt `
  --export $export --insights $insights --candidate $candidate.output | ConvertFrom-Json)
node apps/web/scripts/research-publication-preflight.mjs `
  --insights $insights --candidate $candidate.output --receipt $receipt.receipt
```

The output is a **new metadata-only `review-preflight.json` file in Windows TEMP**. Do not commit the input research, candidate, receipt or preflight output. No public assets are enabled and no approval is granted.

## Tests

From `apps/web`:

```powershell
node --test tests/research-publication-preflight.test.mjs
npm test
npm run build
```

Unit tests use the repository's explicitly invented 2099 UI fixture. Only the guarded local workflow touches actual November 2026 archived data.

## Not in this slice

No human approval record, GitHub Actions activation, public research payload, publication endpoint, Pages wiring, newly acquired data, or changes to the public synthetic Explorer. Actual publication requires a separate approval design, editorial review, explicit permission, and deployment-specific safeguards.
