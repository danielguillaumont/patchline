# P3.3B — M03 EPSS coverage of KEV

Status: **source implementation pending local and GitHub CI validation**. No real-data metric values published.

## Definition and grain

`analytics_marts.m03_epss_coverage_of_kev` is a **view** with exactly one row
for the pinned CISA KEV catalog and the pinned FIRST EPSS score-date population.
It derives its counts from the validated full-union `int_kev_epss_overlap` model:

- **Metric ID:** `M03`; unit: percent, not probability.
- **Numerator:** count of KEV CVEs with an EPSS score on the paired EPSS date.
- **Denominator:** all distinct CVEs in the selected KEV catalog.
- **Unmatched:** denominator minus numerator; never dropped from coverage.
- **Coverage:** `100.0 * numerator / denominator`, without early rounding.
- **Zero denominator:** percentage is `NULL` (undefined), not zero.
- **Dates/provenance:** both snapshot IDs, official KEV catalog release date,
  EPSS source score date, both UTC retrieval timestamps and EPSS model version.
- **Population/filter:** selected KEV snapshot; exact CVE match against the
  complete paired EPSS population. EPSS-only CVEs do not enter the denominator.

A matched score is not proof of exploitation, a missing score is not proof of
safety, and this percentage is **not** a risk score or model-accuracy metric.
No severity ranking, watchlist cutoff, imputation or precision truncation occurs.

## CI and local acceptance

The offline fixture has **3 synthetic KEV entries** and **4 synthetic EPSS
entries**, with 2 CVEs matched and 1 unmatched KEV CVE. Therefore M03 must
produce numerator=2, denominator=3, unmatched=1 and an unrounded percentage
near 66.6666666667. These are fabricated test values, not public vulnerability
statistics. The 2 EPSS-only CVEs are excluded from the denominator.

The existing GitHub Actions `dbt offline fixture` job must run all dbt models
and tests, then `verify-m03`, using an isolated DuckDB fixture path. The new
SQL tests reconcile source counts, date lineage, bounds and zero-denominator
semantics. Python fixture tests verify that missing models fail closed.

Do **not** commit a generated `.duckdb` file or claim a real-data result until
a separate execution on validated archived feeds has been inspected.

**SQL implementation:** `dbt/models/marts/m03_epss_coverage_of_kev.sql`.
**Tests:** `dbt/tests/assert_m03_reconciliation.sql` and
`dbt/tests/assert_m03_semantics.sql`.
