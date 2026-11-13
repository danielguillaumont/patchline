# EA-05B3 — Manual review and publication of three fictional Explorer records

## Scope and release decision

This checkpoint is a **publicly visible fictional-interface demonstration**, not real NVD, CISA KEV or FIRST EPSS observations. The three `CVE-2099-*` identifiers are deliberately invented. No source-archive attestation, predictive scoring, live ingestion, organizational exposure or production vulnerability intelligence is claimed.

The repository owner's manual approval is recorded **only** in `apps/web/fixtures/explorer-public-approval.v1.json`. It must contain `approved:true`, `approved_by:repository_owner`, a concrete UTC timestamp and the owner's own substantive review note. The source candidate remains `public_release_approved:false`. Approval is a reviewed Git change, **not** a cryptographic signature and **not** authorization of any other datasets.

## Reviewed records

- `CVE-2099-0001`: fictional network service, KEV example added 2026-01-10, explicit zero-valued EPSS and percentile; CVSS 3.1 score 9.8 and 4.0 unscored. Its fictional values do not indicate real exploitation.
- `CVE-2099-0003`: fictional application component, KEV example added 2026-01-11, **missing** EPSS and no CVSS metrics. Missing is not numerical zero.
- `CVE-2099-9999`: fictional pending analysis record, no KEV listing, no EPSS observation and no CVSS metrics.

All reference dates and `v-ci-synthetic` model label are fictional demo context. The candidate source is `apps/web/fixtures/explorer-public-candidate.v1.json`, canonical SHA-256 `79901457953bcfb1d29999aca7b79e03f0f1005f1ed771a5eba72a976d3f07af`. No candidate bytes or code paths for the real local NVD/KEV/EPSS bundles are included in the public Explorer.

## Release workflow and proof obligations

1. Review the read-only output from `node apps/web/scripts/review-fictional-explorer.mjs`, including **all** labels, statuses, dates, model labels, caveats and metrics.
2. The repository owner must explicitly opt in to public release using the guarded EA-05B3 Windows installer. A user-provided 24–500 character review note and execution UTC timestamp are written to the approval file. No installer can independently establish that a human read the content; the confirmation records a user decision.
3. Verify frontend tests, TypeScript/Vite build, Python regression/Ruff, synthetic v2 aggregate exports, approved-only staging in an isolated temporary directory, the exact static Pages artifact inventory, and production-path Playwright tests.
4. Stage exactly five changes: the separate approval record, this document, the review command, release-state tests and the Pages browser-test extension. No Git commit, push or deployment is performed by the installer.
5. Review the staged diff and the pull-request CI results. The PR merge triggers Pages publication because the current GitHub Pages workflow deploys on pushes to `main`. **Do not merge until the repository owner intends immediate publication.**
6. After CI and merge, verify `https://danielguillaumont.github.io/exploit-atlas/` and the two allowlisted JSON resources under `/exploit-atlas/explorer/`. Confirm three fictional records, live filtering, label visibility, mobile layout and no real CVE bundles. If deployment fails, stop and inspect GitHub Actions instead of weakening validation gates.

## Explicit non-goals

No live NVD/KEV/EPSS refresh, no public real-CVE release, no risk prediction, no claim about current exploits, and no changes to the aggregate-v2 demo semantics.
