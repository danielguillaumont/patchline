# P3.3A: KEV–EPSS CVE universe join

Status: implementation pending local and GitHub CI validation; **no production metric results claimed**.

## Model

`dbt/models/intermediate/int_kev_epss_overlap.sql` materializes as a **view** at
`analytics_intermediate.int_kev_epss_overlap`. It joins the two existing staging
views by exact `cve_id` with a **full outer join** and one CVE per union member.
It never overwrites or mutates the raw `main` tables. The `analytics_staging`
views remain unchanged. This is descriptive association, not a risk model.

The selected inputs are the single pinned KEV snapshot and the complete single
EPSS score-date population established in P3.1/P3.2. The current warehouse
has no multi-snapshot selection interface; combining additional snapshots
requires an explicit future selection contract, **not** a cross-date join.

| `join_status` | KEV membership | EPSS score present | Interpretation |
|---|---|---|---|
| `both` | yes | yes | A KEV CVE also has an EPSS score for the selected date |
| `kev_only` | yes | no | KEV CVE has no score in this EPSS population |
| `epss_only` | no | yes | EPSS-scored CVE absent from this KEV catalog |

`is_kev` and `has_epss_score` are independent booleans. Both snapshot IDs are
recorded on every output row to identify the **paired data context**; source-
specific values, source dates and retrieval timestamps are NULL where that
source does not contain the CVE. In particular, **NULL EPSS differs from zero**.
No imputation, ranking, watchlist threshold, or proprietary risk score occurs.
The KEV catalog release date is not exploitation onset; an EPSS probability is
not a confirmed exploitation event.

## Validation and acceptance

- `dbt run` creates two staging views and the intermediate union view.
- `dbt test` checks model uniqueness, non-null fields, accepted categories,
  complete union membership and join/lineage/null semantics.
- `python -m patchline.fixtures.ci_warehouse verify-joins --output <path>`
  checks a **synthetic** fixture with precisely **2 both, 1 kev_only, 2 epss_only**,
  including a legitimate zero EPSS score and boundary score 1.
- The GitHub `dbt offline fixture` job runs all models and tests then verifies
  staging and intermediate models against the synthetic database.
- `uv run --locked pytest` and `uv run --locked ruff check .` must pass.

`PATCHLINE_DUCKDB_PATH` must refer to a **separate synthetic fixture database**
for the CI command sequence. Don't test the join by replacing the real database.
The new dbt model is a view; using it against the real archived source pair
remains an explicit, separate validation milestone.

The first released metric should be **M03 (EPSS coverage of KEV)**, calculated
later with an explicit numerator, denominator, dates, missing count and SQL
reference. The join itself is not a released metric.
