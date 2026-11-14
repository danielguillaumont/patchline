# Portfolio screenshots and publication evidence

## Original Exploit Atlas README screenshots — November 13, 2026

The currently featured README images are cropped captures from the running Exploit Atlas synthetic v2 demo, manually reviewed at desktop and mobile widths after EA-02B. They are not mockups, generated vulnerability measurements, or screenshots of the archived real-data study. Cropping removed browser chrome and DevTools; no interface elements or data were inserted or altered.

- `docs/assets/exploit-atlas-hero.png`: branded Intelligence Brief and synthetic KEV/EPSS coverage example
- `docs/assets/exploit-atlas-brief.png`: explanation, interpretation limits, and glossary
- `docs/assets/exploit-atlas-glossary.png`: expanded glossary definition and EPSS distribution entry
- `docs/assets/exploit-atlas-mobile.png`: narrow viewport view of the Intelligence Brief

These are curated captures of an actual running local browser. The mobile capture was cropped from Chrome's fitted device-emulation preview and is lower resolution than a native Playwright screenshot. A future automated capture workflow should replace it with a direct 390 x 844 PNG from Chromium and a separately inspected screenshot of the M05 cohort comparison.

The existing `npm run portfolio:shots` job below is the **legacy P5.2 screenshot procedure**. It still writes the original `spectral-index-*` assets and intentionally does not overwrite them. Do not present those older assets as current Exploit Atlas branding.

The earlier [P5.2 portfolio-proof guide](portfolio-proof.md) documents the legacy screenshot generator and its historical outputs. The README now embeds only reviewed `exploit-atlas-*` assets.

## EA-05C2 public fictional Explorer captures — November 14, 2026

- `docs/assets/exploit-atlas-explorer-desktop.png`: direct 1440 x 900 viewport screenshot after loading the approved fictional Explorer from the isolated `/exploit-atlas/` production Pages build.
- `docs/assets/exploit-atlas-explorer-mobile.png`: direct Playwright element screenshot of the full fictional Explorer at a 390 px viewport, with the invented pending-analysis record selected.

The automated capture requires the approved synthetic fixture, uses real browser rendering, refuses to overwrite existing curated images, verifies PNG headers/dimensions, and publishes the pair only after successful generation. These images are **not** archived real-source CVE measurements; they contain exactly the three approved invented CVE-2099 records. No synthetic values or screen elements are added afterward.
