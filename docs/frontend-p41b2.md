# P4.1B2: Artifact Evidence Inspector

Status: source slice for `feat/p41b-evidence-interactions`, after P4.1B1. No source model, export format, dependency, or backend change.

## Purpose

The Methods & Quality view now includes an interactive artifact register sourced from the existing export manifest. It lists the nine recorded artifacts: the M03 KEV coverage, M04 EPSS population summary, and M04 EPSS score bands, each in CSV, JSON, and Parquet. Select an artifact to inspect its recorded path, model, format, row count, byte size, ordered column names, and full SHA-256 digest.

## Trust and provenance boundaries

- The browser validates the expected nine model/format combinations, unique paths, nonnegative integral sizes and row counts, digest format, nonempty unique column names, and expected mart row counts (1, 1, and 5).
- The manifest's four validation counters must agree with the validated analytical outputs.
- The browser does not fetch the CSV or Parquet files and does not calculate any SHA-256 digest. The displayed digest is explicitly labeled as a *recorded manifest value*, not a verified browser result.
- Cryptographic verification must run against the complete local export bundle, using `uv run --locked python -m patchline.exports.analytics verify --output <export-directory>` before publishing data.
- The local web demo only includes `manifest.json` and three approved JSON mart exports. Do not publish raw source archives, CSV, or Parquet by default.
- No CVE-level claims or real-time vulnerability status are inferred from these aggregate artifacts. A fixture remains labeled synthetic.

## Review and acceptance

Run `npm test` and `npm run build` from `apps/web`. On Atlas, ensure the five selectable EPSS bands still work. In Methods & Quality, select at least one JSON, CSV, and Parquet artifact. Check keyboard Tab and Enter/Space, active selection, digest wrapping, and that the file metadata actually changes. Review 1440 x 900, 768 x 1024, 390 x 844 and 320 x 700 viewports. Confirm the entire page has no horizontal overflow.

The next slice should add Playwright browser coverage for the interaction states and responsive screenshots. No em dashes should be introduced into project copy.
