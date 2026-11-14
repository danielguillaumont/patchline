# EA-02C3 — Pinned, offline archived-aggregate publication candidate (slice 1)

## What this checkpoint adds

A conservative **review-only metadata candidate** for EA-02C2's local historical KEV/EPSS insight JSON. It does **not** turn research into a public release. It hashes the exact input bytes and records snapshot identities, source dates, and the three insight IDs while **not copying the archived explanations, numerical findings, or original JSON into Git**.

The existing browser-side contract is reused to reject malformed content, unsupported risk claims, incorrect denominators, and fabricated publication approvals. The candidate includes `public_release_approved: false`, `source_archives_reverified_by_this_tool: false`, and `publication_scope: not_for_publication`. No GitHub Actions workflow, Pages build, public site entrypoint, or approval record is changed.

## Windows PowerShell local review

First independently verify the original source archive and the insight file with the existing Python CLI (per EA-02C1 and EA-02C2). This tool does **not** do that verification.

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
node .\scripts\research-publication-candidate.mjs --input "$HOME\Downloads\ea02c2-archived-insights-2026-11-11.json"
```

The command prints a fresh manifest path in the Windows TEMP directory and the pinned input SHA-256 digest. It does not upload data, change the repository, copy the archived JSON or approve publication. Keep this manifest **local**; do not add it or the real insight file to Git.

To run checkpoint tests:

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
node --test .\tests\research-publication-candidate.test.mjs
npm test
npm run build
```

## Still required before any public aggregate release

- Independently verify the original 12-artifact v2 exports and the archived insight JSON using the Python CLI, including source/archive provenance.
- Review the exact pinned input bytes, all calculations, caveats and source timestamps.
- Implement and separately review a public payload contract and an explicit approval gate, ensuring historical figures cannot be mistaken for live assessments.
- Run browser and production-build release-gate tests; obtain deliberate approval before enabling a deployment.

The invented test JSON with 2099 source dates is **only a test fixture**, not historical evidence. The presence of a candidate manifest is not verification or permission to publish.
