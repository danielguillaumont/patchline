# EA-05C1 — Public Explorer UX hierarchy

## Goal

Make the approved **fictional** CVE Explorer easier to inspect on desktop and small screens without changing data handling, approved records, manifests, source classification, or release gating.

## Scope

- Tighten the hero typography, padding, and fictional-data stamp so the search controls appear sooner.
- Clarify selected records, detail panel hierarchy, form focus affordances, and the distinction between interactive controls and passive labels.
- Keep the current Exploit Atlas purple / lime visual identity; no new dependency or design system.
- Improve the mobile result/detail reading flow and respect reduced-motion settings.
- Extend the existing **production Pages** browser suite with desktop and mobile behavior checks.

## Explicit boundaries

The underlying dataset is still **three invented CVE-2099 examples**. There is no live NVD, KEV, or EPSS API; no real-world CVE-level publication; no new risk scoring or organizational exposure claim. The existing owner-approved candidate digest, approval JSON, release guards, and Pages workflow are unchanged.

## Files

- `apps/web/src/explorer-local.css` — shared local/public Explorer styling only.
- `apps/web/tests/e2e/pages-preview.spec.mjs` — two additional Playwright tests (each browser project).
- `docs/ea05c1-explorer-ux-hierarchy.md` — scope and validation notes.

## Review / acceptance

1. Verify exact modified-file inventory and no staged pre-existing changes.
2. Run the frontend unit suite and TypeScript production build.
3. Produce the approved synthetic Pages build in an isolated directory and verify the static publication boundary.
4. Run the complete Pages Playwright suite; confirm no desktop/mobile horizontal overflow and working selection/filters.
5. Run the Python regression and Ruff checks to detect collateral breakage.
6. Stage exactly the three reviewed paths; do **not** automatically commit, push, merge, or deploy.

Human review of the staged diff and CI results is required before the next PR merge.
