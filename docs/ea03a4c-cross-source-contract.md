# EA-03A4C — Source-selection compatibility gate (no joins)

**Schema ID:** `exploit-atlas.cross-source-selection.v1`
**Status:** offline, local-only inspection of two existing DuckDB databases.

## Purpose

Before building any NVD + KEV + EPSS CVE-level mart, validate that the specific inputs have internally consistent identities, dates, row counts and bounded-source provenance. The output is an **eligibility preflight**, *not* an analytical result or permission to publish a joined dataset.

## Data boundaries

- The KEV/EPSS input is the existing selected-pair DuckDB warehouse. Validate exactly one registered KEV snapshot and one EPSS score-date snapshot, each with a matching raw CVE population and unique identifiers. EPSS score dates, ranges and model-version metadata must agree with the selected registry entry.
- The NVD input is an existing EA-03A4A isolated NVD staging database or the disposable EA-03A4B working copy, inspected **read-only**. Validate one query registry, its staging contract and cryptographic *identifier formats*, exact CVE/metric counts, CVE ordering, page identity, CVSS version and nullable score boundaries.
- Four NVD non-attestation flags must remain false: point-in-time consistency, global coverage, independent source origin and organization asset exposure. NVD is a **bounded query**, not a global source snapshot.
- Dates from KEV and EPSS are not assumed to match NVD acquisition timestamps; source dates are **not** effective dates of first exploitation. A query window may contain records modified during the period and does not represent a complete historical as-of image.
- Cross-source CVEs are **not compared, joined or scored**. No probability is imputed for missing EPSS entries. No preferred CVSS severity is selected.

## Reproduce in Windows PowerShell 5.1

From the repository root:

```powershell
uv run --locked pytest tests/test_cross_source_contract.py
uv run --locked pytest
uv run --locked ruff check .
```

If you have **two separately verified local databases**, set their actual paths. Do **not** run against raw downloads, and do not invent a query ID or use the same database twice:

```powershell
$analytics = 'C:\absolute\path\to\existing-kev-epss.duckdb'
$nvd = 'C:\absolute\path\to\existing-nvd-query.duckdb'
uv run --locked python -m patchline.warehouse.cross_source_contract `
  --analytics-db $analytics --nvd-db $nvd
```

The CLI emits a versioned JSON report only to stdout. It opens both databases read-only and does not create a third database, modify input files, make network requests, run dbt, or publish exports. An invalid source fails with a non-zero exit code.

## Precise confidence boundary

This command checks that the contents of the two provided local database files agree with the expected selection contracts. It **does not re-verify** all upstream KEV/EPSS/NVD raw archives or SHA-256 payloads: hash fields are recorded and format-checked, not independently recomputed against source archives. Use the established upstream verification commands before this preflight. The preflight also cannot show that NVD records represent global coverage or that three sources existed simultaneously at a common as-of date.

## Next checkpoint

**EA-03A4D:** select an explicit time-and-coverage policy, add synthetic negative tests for future-data leakage / partial NVD query coverage, and only then implement a **separate, opt-in, source-scoped** CVE join. Keep the current v1/v2 KEV-EPSS analytical exports and public synthetic demo unchanged until a new reviewed consumer contract is published.
