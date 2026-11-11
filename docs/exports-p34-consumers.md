# P3.4B — Versioned consumer contracts

P3.4A exports carry `schema_id: patchline.analytics-export.v1` in the manifest. P3.4B
adds **local JSON Schema Draft 2020-12** contracts in `src/patchline/exports/contracts/`
for the manifest and all three analytical JSON datasets. Creation validates before
publication, and verification checks the contracts after confirming file SHA-256 digests.
Contract validation requires no network access. Schemas ship with the Python package.

## Consumer instructions

1. Run `python -m patchline.exports.analytics verify --output <bundle>` before importing.
2. Inspect `manifest.json` and require `schema_id` to match exactly. A `synthetic_fixture`
   bundle is for design/testing only; never present it as current real-world data.
3. In each manifest artifact, `columns` is the producer's ordered column set. Use the
   JSON Schemas for core stable fields and constraints; additional descriptive fields
   may appear in the marts. Treat JSON files as arrays, including one-row summary views.
4. Numeric `epss` values/quantiles are **probabilities from 0 to 1**, whereas
   `coverage_percent` and `population_percent` are **percentages from 0 to 100**.
   When the population denominator is zero, percentages are `null`, not zero.
5. Source dates and snapshot IDs in the manifest and datasets describe the paired
   selected snapshots. They do not claim freshness or live exploitation.
6. For Power BI prefer typed Parquet, or CSV with explicit column types. For the
   Spectral Index frontend, consume JSON only after manifest verification and
   always display synthetic/archived-source classification prominently.

## Contract evolution

Schemas define required core fields and numeric boundaries. They deliberately allow
additional descriptive fields while preserving the current `v1` export format. Changing
existing field meaning, units, or null policy requires a new manifest schema ID and a
corresponding versioned consumer migration. Hashes detect accidental changes only:
this is **not a signed attestation or external authentication** of a bundle.

No new raw source ingestion, online refresh, or consumer UI is introduced in this slice.
