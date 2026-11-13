# EA-05B2: Reviewed fictional Explorer / Pages activation gate

**Baseline:** PR #48 squash merge `0da5288098867815ae27d01546ad1b88342d71c5`.
**Branch:** `feat/ea05b2-public-explorer-activation`.
**Publication state of this checkpoint:** **PENDING REVIEW, NOT DEPLOYED**.

## Purpose

Connect the already implemented EA-05A React Explorer to a separately controlled static release of the three deliberately invented `CVE-2099-*` examples. Keep the existing aggregate v2 Pages demo intact, and never treat EA-03A4E2 local CVE bundles or historical source archives as public data.

## Exact approval boundary

- `apps/web/fixtures/explorer-public-candidate.v1.json` is **always** the unapproved EA-05B1 source candidate. Its `public_release_approved` stays `false`.
- The canonical candidate SHA-256 is pinned to `79901457953bcfb1d29999aca7b79e03f0f1005f1ed771a5eba72a976d3f07af`. Any record edits require a new review contract and code change. Merely changing the manifest checksum cannot approve altered source data.
- The separate file `apps/web/fixtures/explorer-public-approval.v1.json` begins with `approved:false`, null reviewer, timestamp and review note. **This is intentionally not a release authorization.**
- A *later, separate review* of the exact three fictional records is needed before the repository owner sets `approved:true`, `approved_by:"repository_owner"`, a concrete ISO UTC `approved_at_utc` and a substantive `review_note` of 24–500 characters. Review the PR containing that change before merging; the approval fields express reviewed repository policy, **not a cryptographic signature**.
- The Pages pipeline reads the on-disk approval file; no free-form environment variable can turn pending approval into a public dataset. It derives a new `exploit-atlas.public-explorer-data.v1` artifact and a SHA-256 manifest only after approval. The original candidate is never copied to Pages.

## Deployment guarantees

1. The existing Pages CI first builds and independently verifies the **synthetic aggregate v2** exported demo, preserving the original exact-five-file `/demo` contract.
2. `stage-public-explorer.mjs` is invoked against the *isolated* CI staging directory. With pending approval it writes nothing; after approval it writes precisely `explorer/cve-records.json` and `explorer/manifest.json`, refusing a destination inside the repository.
3. `build-pages.mjs` derives `VITE_EXPLORER_PUBLIC_RELEASE` from the verified approval state and exact staged artifact. It refuses an Explorer directory if approval is pending, and refuses missing or tampered artifact bytes if approval is granted. Build-time bypass through a user-provided Vite environment variable is overwritten.
4. `verify-pages-dist.mjs` requires exact demo files, exact root file inventory, and, only after approval, the exact two public fictional Explorer files. No general-purpose archive, CSV/Parquet or local CVE export is allowlisted.
5. React fetches those two `/explorer` files at the repository's Vite `BASE_URL` and compares the record bytes to the manifest SHA-256 through Web Crypto before displaying the examples. Browser digest comparison is **not independent trust attestation**; the pinned source and CI dist checks are the trusted release boundary.
6. Production Playwright tests cover both approval states at the actual project base (`/exploit-atlas/`), plus the existing v1/v2 and local-only Explorer suites. The `CVE-2099` IDs, dates, KEV/EPSS/CVSS details are fictional and carry no claims about current NVD, CISA KEV, FIRST EPSS, prediction accuracy, or asset exposure.

## Manual review protocol for a later checkpoint

Review `apps/web/fixtures/explorer-public-candidate.v1.json`, confirm all three records remain fictional and claims remain accurate, compare the pinned SHA-256, and separately authorize the exact candidate. **Do not change the approval file as part of EA-05B2.** On a later approval PR, run the full frontend tests, a fresh synthetic Pages build, static distribution verification and Playwright tests at `/exploit-atlas/` before merging. The approval commit will be the change that makes the public Explorer visible.

## Validation commands

From `apps/web`:

```text
node --test tests/explorer-release.test.mjs tests/explorer-public-model.test.mjs
npm test
npm run build
```

The main Windows installer performs a clean temporary synthetic aggregate Pages build, checks the withheld Explorer route, validates the Pages output and replays browser suites. The package does not commit, push, merge, change the approval state, or publish a release.
