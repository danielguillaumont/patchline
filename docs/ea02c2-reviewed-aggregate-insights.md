# EA-02C2 — Local Archived Insight Review Desk

## Purpose

Turn the three **independently verified, archived aggregate** CISA KEV/FIRST EPSS findings from EA-02C1 into accessible, evidence-led explanatory cards. This checkpoint is a **nonpublishing editorial preview**, not a data approval or a GitHub Pages release.

The reviewer opens `apps/web/research-review.html` through the Vite **development server**. Its React entry point is separate from `src/main.tsx`, which powers the public site. Vite's default single-entry Pages build does not include this document or the local React reviewer. No real insights JSON, KEV data, EPSS rows, output exports, or research output hashes are added to Git.

The review UI accepts a **user-selected local JSON file** using a file input. It parses the content in memory only, with no `fetch()` or upload endpoint. It renders 3 findings including a headline, simple explanation, counts and denominators, why it matters, next question, caveat, and the exact source provenance. Visual bars represent percentages with **different and overlapping denominators**; they are descriptive, not independent samples or risk scores.

### Validation boundaries

- The `.mjs` contract verifies exact fields, classification, source IDs, percentages, record counts, coverage, supported thresholds, and three fixed insight IDs. It rejects unknown prediction or risk fields, forged public approval, and mismatched denominators.
- **Browser validation is not cryptographic archive verification.** First run the Python `patchline.exports.analytics verify` and `patchline.research.insights verify` commands against the original 12-artifact local v2 bundle, as done during EA-02C1. The reviewer does not authenticate data by itself.
- The committed `apps/web/tests/fixtures/research-review-invented.json` is **invented UI test data only** (2099 timestamps and placeholder SHA IDs), not a claim about real archived sources. The verified November 2026 insights remain in the user's private Downloads directory.
- No publication authorization is added; `public_release_approved` must remain `false` and `publication_scope` must remain `local_review_only`. A separate, explicit reviewed-publication milestone would be required to publish *even aggregates*.
- No live data, affected inventory, attribution, exploit forecast, or organizational remediation recommendation.

## Local reviewer walkthrough — Windows PowerShell

From the existing project checkout:

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
npm run dev -- --port 5187 --strictPort
```

Open `http://127.0.0.1:5187/research-review.html` in your browser. Click **Choose insight JSON** and select:

`C:\Users\Daniel\Downloads\ea02c2-archived-insights-2026-11-11.json`

The user's file stays in the local browser tab; it is not copied into the repository. Review all three findings, dates, counts, limitations, and investigate-next prompts before considering a publication design. Stop Vite with Ctrl+C when finished.

## Reproducible automated validation

Run from `apps/web`:

```powershell
npm test
npm run build
npx playwright test --config playwright.research-review.config.mjs
```

Browser tests run desktop and mobile widths with invented data. The default production build must not contain `research-review.html` or its independent TSX module. `uv run --locked pytest -q` and `uv run --locked ruff check .` cover the separate Python research pipeline.

## Next milestone

EA-02C3: a **separate reviewed aggregate publication candidate**, requiring exact pinned insight bytes, provenance review, explicit scope approval, and a public display with unambiguous historical timestamps. Do not publish the archived insight JSON without that checkpoint.
