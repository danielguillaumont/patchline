# P5.2A: Portfolio proof and reproducible screenshots

This is a publication workflow, not a new vulnerability data source. All four
README screenshots are taken from a verified **synthetic v2 fixture** using
Chromium and the real Spectral Index frontend.

## Screenshot capture (Windows PowerShell 5.1)

Use **PATCHLINE MAIN** from the repository root to install the existing locked
Python dependencies once:

```powershell
uv sync --locked --python 3.12
```

Stop the normal port 5173 Vite server in **PATCHLINE FRONTEND** only if you are
installing npm dependencies. The capture itself runs an isolated Vite server
on port **5175** and does not use port 5173 or overwrite your local demo files.

From **PATCHLINE MAIN**:

```powershell
Push-Location apps/web
npm ci
npx playwright install chromium
npm run portfolio:shots
Pop-Location
```

The screenshot runner creates a fresh temporary DuckDB database, runs and tests
dbt, exports and verifies the **v2** bundle, and launches the web UI using only
its isolated synthetic fixture. It refuses to overwrite existing screenshots.
It writes these files only after all four browser captures succeed:

- `docs/assets/spectral-index-atlas.png`, desktop, 1440 x 900 viewport
- `docs/assets/spectral-index-cohort.png`, desktop M05 comparison panel
- `docs/assets/spectral-index-evidence.png`, desktop M05 artifact evidence
- `docs/assets/spectral-index-mobile.png`, mobile, 390 x 844 viewport

The README intentionally links to these exact paths. Do not stage or commit
`README.md` until the screenshot runner has produced all four images and you
have reviewed them. The existing v1/v2 browser tests remain independent.

## Publication checks

Inspect the four images before committing. Confirm:

- The **SYNTHETIC FIXTURE** classification appears on the Atlas screenshot.
- The cohort comparison uses 4 full EPSS CVEs, 2 scored KEV CVEs and a separate
  unscored KEV category; it does not describe those values as live metrics.
- The evidence screenshot labels SHA-256 as manifest-recorded metadata, **not
  browser-verified** content.
- The mobile image is readable, contained within 390 pixels, and has no Chrome
  DevTools, terminal windows, local paths or private data in the frame.
- All images are crisp at their intended width and belong to the current v2 UI.

If changes are needed, keep the original images for review and generate a new
set deliberately. The command intentionally prevents silent overwrites.
`docs/assets/` images are the only generated binary assets intended to be
committed. Do not commit `apps/web/public/demo`, local warehouse databases,
Playwright reports, or downloaded vulnerability feeds.

## Why this matters

The README should prove the pipeline, product UI, and integrity boundary in the
first screen of the repository. The curated images are actual browser renders
of tested frontend source, not visual mockups or independently invented data.
