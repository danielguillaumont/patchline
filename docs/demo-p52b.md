# P5.2B1: One-command local synthetic demo

The Windows PowerShell 5.1 launcher builds and verifies a **synthetic v2**
Patchline export and serves Spectral Index on a local loopback address.
It does not download live feeds or use archived real-source data.

## Prerequisites

- Windows PowerShell 5.1, Node.js 22 or newer, and `uv` on PATH
- Python 3.12 available to `uv`; network access may be required for first install
- TCP port 5173 available (stop PATCHLINE FRONTEND first)
- `npm ci` is automatically run on the first launch if Vite is missing

## Run

From the repository root in **PATCHLINE MAIN**:

```powershell
.\scripts\Start-PatchlineDemo.ps1
```

If port 5173 is occupied, stop the existing Vite server or use a separate port:

```powershell
.\scripts\Start-PatchlineDemo.ps1 -Port 5174
```

The launcher uses `uv run --locked` for a deterministic Python toolchain, then:

1. Creates a new uniquely named temporary directory and DuckDB fixture.
2. Runs all dbt models and tests.
3. Checks M05 cohort reconciliation.
4. Creates a complete twelve-artifact v2 export and verifies its hashes.
5. Checks `synthetic_fixture` classification and twelve expected artifacts.
6. Copies only the manifest and four JSON marts to a temporary public directory.
7. Starts Vite with the existing isolated `vite.e2e.config.mjs` publicDir.
8. Checks that the manifest is served and prints the local URL.

Open the printed URL and confirm the classification banner says
**SYNTHETIC FIXTURE** and `patchline.analytics-export.v2`.
The numbers are invented regression fixtures, not current security measurements.

Keep the terminal open while using the UI. Press **Ctrl+C** to stop Vite and
remove the temporary fixture, export, and public directory. A forcibly killed
process may leave a temporary `patchline-local-demo-*` directory under the OS
Temp directory; it does not modify the repository or its archived data.

## Safety and compatibility

- The launcher does **not** touch `apps/web/public/demo`.
- No CSV, Parquet, downloaded KEV/EPSS feeds, or temporary browser reports are
  committed, copied to the repository, or served from the web frontend.
- A second Vite server is not started silently if the requested port is in use.
- It always uses the v2 synthetic contract. The normal v1/v2 consumer tests
  and the original export CLI remain unchanged.
- Local readiness checks validate manifest classification; the Python export
  verifier performs the actual hash and schema checks before anything is served.

## Acceptance checklist

Run `npm test` from `apps/web` and check the new demo-guard tests.
Run the launcher, open the displayed address, and verify the Atlas, M05 cohort
comparison, and evidence register. Press Ctrl+C. Check that the normal Vite
frontend still launches on 5173 and that `git status --short` contains only the
five source additions from this slice.
