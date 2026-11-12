# P5.2C1: GitHub Pages static showcase preflight

This milestone builds a **reviewable Pages-ready artifact**, not a public deployment.
The site must load at `/patchline/` and display only **synthetic_fixture** data.
No real archived KEV or EPSS records are published.

## Build contract

1. Generate a fresh synthetic warehouse and run dbt models and tests.
2. Verify M05 reconciliation and create the v2 twelve-artifact export.
3. Use the Python exporter to verify the full bundle, including file hashes.
4. Stage only `manifest.json` and the four JSON marts with the Node staging tool.
5. Cross-check the JavaScript consumer schema, all twelve source artifact digests,
   and the exact synthetic classification before the staging directory is created.
6. Build Vite with the repository base path `/patchline/`.
7. Verify the generated static HTML, manifest, four JSON marts and their hashes.
8. Run Playwright tests against the production bundle under `/patchline/`.

The staging tool refuses to overwrite existing demo data. GitHub Actions stages
all five JSON files under its isolated runner temp directory, then passes that
directory to `vite.e2e.config.mjs`. It never populates or changes the regular
`apps/web/public/demo` directory. Its output is an ordinary CI artifact for
review, not a Pages release. No Pages secrets or deployment permissions are required for P5.2C1.

## Local test after generating a verified v2 export

From the repository root (Windows PowerShell 5.1), with `$exportDir` set to
an existing complete verified synthetic v2 export directory:

- Create a fresh temporary directory for the public fixture, such as
  `$publicDir = Join-Path $env:TEMP ("patchline-pages-" + [guid]::NewGuid().ToString("N"))`.
- `node apps/web/scripts/stage-pages-data.mjs --exports $exportDir --destination (Join-Path $publicDir "demo")`
- `cd apps/web`
- Set `$env:PATCHLINE_E2E_PUBLIC_DIR = $publicDir`.
- `npm test`
- `npm run build:pages`
- `node scripts/verify-pages-dist.mjs --dist dist`
- `npx playwright test --config playwright.pages.config.mjs`

This path avoids modifying an existing local demo folder. The static build only
contains the five explicitly staged JSON files. Review and remove the temporary
fixture directory manually after testing, never an unrelated directory.

## Data integrity

The static site serves five JSON files only. The manifest still describes all
twelve v2 artifacts. The evidence inspector correctly identifies recorded
hash metadata as not browser-verified. SHA-256 comparisons happen during build.
The frontend and all existing local demo commands retain the `/` base path.

## Next milestone

P5.2C2 can add `actions/deploy-pages` after this preflight passes, the public
Pages source is configured as GitHub Actions in repository settings, and the
URL is inspected in a real browser. Do not add a public link before deployment.
