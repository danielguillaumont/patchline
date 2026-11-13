# EA-03A4D1 — Temporal and bounded-coverage safeguards

**Contract:** `exploit-atlas.time-coverage-preflight.v1`

**Scope:** offline-only, existing local DuckDB files; no joined CVE data or public export.

## Why this checkpoint exists

EA-03A4C validates the independent input selections, but it does **not** prove a common historical as-of date. NVD currently represents one bounded query, with records that may have been modified after the period one wants to study. A naive CVE join could silently mix future observations into older KEV and EPSS data or imply that absent NVD results mean the vulnerability does not exist.

EA-03A4D1 makes those restrictions executable before any join is developed. It first repeats EA-03A4C's read-only selection gate, then examines **source-local dates only**. It never joins CVE rows across sources.

## Exact policy

- The caller must supply a canonical `YYYY-MM-DD` analysis cutoff and explicitly acknowledge NVD's bounded query scope.
- KEV catalog source date and EPSS score date may not be later than the cutoff.
- KEV and EPSS recorded UTC retrieval timestamps must not fall on a calendar date after the cutoff. UTC offsets are interpreted in UTC.
- Every KEV raw `date_added` must be a valid date on or before the cutoff.
- Every NVD normalized CVE `published_source_timestamp` and `modified_source_timestamp` must parse as a complete timestamp whose calendar date is not after the cutoff. If the source timestamp includes an offset, comparison uses its UTC date. NVD timestamps without offsets are compared by the date they show; the policy **does not infer a verified timezone**.
- NVD row identities and KEV snapshot identities are checked again as read-only inputs; counts must still match their preflight selections.
- All four NVD non-attestation flags must remain false. The output always states that NVD coverage is **bounded**, not global, and that absence outside a query is unknown.
- If any check fails, the CLI exits nonzero with a JSON failure reason. A successful response is a **preflight result only**, never permission to reconstruct history, claim organization-specific exposure, publish data or perform a join.

**Important epistemic limit:** Even if all dates are on or before the cutoff, we do not have a verified NVD acquisition timestamp in the EA-03A4A staging registry and cannot reconstruct the historical state of a CVE record as it existed at that cutoff. This is a calendar-date guard, **not** point-in-time historical validation. This command also does not rehash original upstream archives. Use EA-03A4A's full verification separately.

## Reproduce (Windows PowerShell 5.1)

From the repository root:

```powershell
uv run --locked pytest tests/test_cross_source_policy.py
uv run --locked pytest
uv run --locked ruff check .
```

With **two previously verified, different** local DuckDB files (replace both paths):

```powershell
$analytics = 'C:\absolute\path\to\kev-epss.duckdb'
$nvd = 'C:\absolute\path\to\nvd-query.duckdb'
uv run --locked python -m patchline.warehouse.cross_source_policy `
  --analytics-db $analytics `
  --nvd-db $nvd `
  --cutoff-date 2026-01-15 `
  --acknowledge-bounded-nvd
```

`2026-01-15` above is an **example cutoff only**. Choose one appropriate to the actual source files. Do not treat a passing sample test as verification of downloaded archives or of NVD coverage beyond the selected query. Never use the same database twice. The CLI prints JSON to stdout and does not create files, make network requests, change source tables, run dbt or publish exports.

## Next checkpoint

**EA-03A4D2** may introduce a **separate, explicit opt-in, bounded-query CVE-level join**, but only with its own versioned output semantics and tests that preserve missing EPSS values, CVSS metric versions and NVD query coverage limitations. Nothing in the current v1/v2 KEV-EPSS analytical exports or public synthetic GitHub Pages demo should change in this slice.
