# EA-05B1: Bounded fictional public Explorer candidate

**Checkpoint:** `feat/ea05b-public-synthetic-explorer` (first slice)
**Baseline:** PR #47 merge `b208cd6ad9d7de1836fb4eb761a17c7f782547bb`
**Contract:** `exploit-atlas.public-explorer-candidate.v1`

## Goal

Establish a deliberately separate and testable **publication candidate** for the CVE-level Explorer. This is **not a publication approval** and does not modify GitHub Pages. The candidate is never sourced from EA-03A4E2's local consumer bundle or the source archives.

## Data and attribution

The three `CVE-2099-*` records are hand-curated fictional teaching examples with invented summaries, dates, KEV membership, EPSS observations and CVSS metrics. They intentionally mirror the three development-only examples so the next frontend step can reuse the tested interactions. The dates are illustrative, not historical NVD / CISA KEV / FIRST EPSS snapshots. CVE-2099 identifiers are examples, not real vulnerability claims. No source-archive attestation, completeness claim, asset exposure or risk score is asserted.

The seed is **not** labeled approved: `public_release_approved: false`. Candidate manifests and generator output retain the same unapproved status. The later release change must include human review of the exact payload, separate public artifact approval, and Pages-specific validation before enabling the public Explorer.

## Contract and verifier

- The seed and manifest have strict field allowlists, fixed fictional CVE membership, explicit data classification and consistent KEV / EPSS / CVSS null semantics.
- Canonical UTF-8 JSON and SHA-256 identify byte-for-byte candidate outputs across machines.
- Verification checks manifest identity, source-seed equivalence and both exact file names; recomputing a checksum after altering the candidate does not bypass the seed comparison.
- The generator writes only to a **new direct child of the system TEMP directory** starting `exploit-atlas-ea05b-`, refuses overwrite, and does not modify `apps/web/public`, `dist`, Pages workflows, or runtime React code.
- SHA-256 here attests **candidate file reproducibility against this committed fictional seed**, not trust in empirical data or the provenance of real source archives.

## Reproduce locally

From `apps/web`:

```powershell
$destination = Join-Path $env:TEMP ("exploit-atlas-ea05b-" + [guid]::NewGuid().ToString("N"))
node scripts/explorer-public-bundle.mjs create --output $destination
node scripts/explorer-public-bundle.mjs verify --output $destination
```

For focused tests: `node --test tests/explorer-publication.test.mjs`.

## What EA-05B1 does not deliver

No production runtime toggle, no Pages data staging, no live NVD/KEV/EPSS ingestion, no new historical dataset, and no new public claims. Existing EA-05A local Explorer remains development-only, and the existing approved synthetic aggregate demo remains unchanged.

## Next checkpoint

EA-05B2 will require an explicit review/approval boundary and an allowlisted static data route, production build verification of its exact bytes, browser checks on `/exploit-atlas/`, and cross-checks ensuring EA-03A4E2 candidate exports cannot leak into Pages.
