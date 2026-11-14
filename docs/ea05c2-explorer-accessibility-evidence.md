# EA-05C2 — Accessible Explorer selection and portfolio evidence

## Goal

Close the portfolio documentation gap after the approved EA-05B3 public fictional Explorer and EA-05C1 layout changes. Make record selection less noisy for assistive technology, show current Explorer images in the GitHub README, and avoid changing publication contracts.

## Implemented scope

- Result buttons explicitly control the selected record detail region (`aria-controls` + stable ID), and a short screen-reader status reports the current fictional record. Avoid announcing the entire detail panel on every selection.
- Production-path browser test covers keyboard selection, accessible status, filter changes, and zero-versus-missing EPSS semantics.
- An isolated `playwright.explorer-portfolio.config.mjs` capture runner creates two screenshots from the already-approved **synthetic** production Pages build: desktop 1440 x 900 and a 390-pixel mobile Explorer view. It refuses to overwrite existing images and validates their PNG bytes.
- README accurately describes the public three-record fictional Explorer, clarifies already-implemented **local-only bounded NVD** work, and embeds a screenshot of the actual interface.
- Screenshot provenance is recorded in `docs/readme-screenshots.md`.

## Strict boundaries

No public real-world CVE data, KEV/EPSS ingestion, approval status, candidate checksum, release scripts, publication workflows, dependency updates, or predictive risk claims. The screenshots are captures of **CVE-2099 fictional examples only**; these are not the separately archived real-data research results.

## Validation / staging gate

Run the frontend unit suite, TypeScript build, Python tests, Ruff, dbt models and tests, approved Pages static build and verifier, complete Pages browser suite, and the new screenshot capture. Review both PNG images before committing. Stage only the eight planned source/document files and two curated images; no automatic push, merge or deployment.
