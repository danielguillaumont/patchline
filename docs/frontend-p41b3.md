# P4.1B3: Isolated Browser Verification

Browser tests cover the verified Spectral Index frontend at 1440px, 390px, and 320px widths, including chart interactions, keyboard selection, manifest evidence, honest Explorer preview, and page-level horizontal containment. The navigation strip can scroll independently on narrow screens.

## Environment and boundaries

- Node.js 22 and `uv` with Python 3.12 are required.
- Install `@playwright/test` from the exact `apps/web/package.json` declaration and commit the generated `apps/web/package-lock.json` in the PR.
- Install Chromium with `npx playwright install chromium`. Playwright documentation uses `npx playwright install --with-deps chromium` in Linux CI.
- From `apps/web`, run `npm run test:e2e`. Playwright automatically invokes `scripts/serve-e2e.mjs` and starts an **isolated Vite server on port 5175**. It does not use or stop the developer's server on port 5173.
- The helper creates a fresh synthetic DuckDB fixture, runs dbt models and tests, creates and verifies an immutable export, then copies only four approved JSON artifacts into a temporary directory. It configures a separate Vite public directory and does **not write to `apps/web/public/demo`**.
- The e2e server refuses to start if port 5175 is already occupied. Do not start it manually.
- Browser screenshots and failure traces go to ignored `apps/web/test-results`, and the HTML report goes to ignored `apps/web/playwright-report`. CI uploads them as build evidence.
- Tests assume the committed deterministic synthetic fixture's 4 scored EPSS CVEs and 66.67% KEV coverage; do not use these assertions for real production data.

## Terminal workflow

**PATCHLINE MAIN** at `C:\Users\Daniel\Projects\patchline` handles installation and tests. Before modifying npm dependencies, stop Vite in **PATCHLINE FRONTEND** with Ctrl+C to avoid Windows file locks. After installing, the standard frontend can be restarted on port 5173. No second manual server is required for Playwright.

The automated checks confirm page-level containment and independently scrollable navigation. Tests do not verify manifest artifact bytes in the browser: the Python exporter verifies them before the temporary demo is served.

## GitHub Actions

The existing frontend job adds Chromium, the Python fixture toolchain, and `npm run test:e2e` after its contract tests and build. New browsers are installed with the Playwright version locked in npm's lockfile. Keep all generated demo data and browser reports out of Git.
