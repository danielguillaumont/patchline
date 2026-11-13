# Data dictionary

Patchline builds a local DuckDB warehouse from one explicitly selected CISA KEV snapshot and one FIRST EPSS score snapshot. Raw source archives and databases remain outside Git.

## Source records

| Field | Meaning |
| --- | --- |
| `raw_kev_snapshot.snapshot_id` | SHA-256 identifier for the selected KEV catalog |
| `raw_kev_snapshot.cve_id` | CVE identifier in the KEV catalog |
| `raw_kev_snapshot.date_added` | Date the CVE was added to KEV |
| `raw_kev_snapshot.due_date` | CISA catalog remediation due date |
| `raw_epss_daily.snapshot_id` | SHA-256 identifier for the selected EPSS archive |
| `raw_epss_daily.cve_id` | CVE identifier in the EPSS scoring population |
| `raw_epss_daily.epss` | Estimated probability of exploitation activity over the next 30 days |
| `raw_epss_daily.percentile` | Relative EPSS ranking, not a probability |
| `raw_epss_daily.score_date` | Source-provided scoring date |
| `raw_epss_daily.model_version` | Source-provided EPSS model version |

## Provenance

The `source_snapshots` table stores each source identifier, snapshot ID, source date, retrieval timestamp, model version where applicable, and validated row count.

## Analytical marts

| Mart | Grain | Meaning |
| --- | --- | --- |
| M03 | One coverage summary | KEV CVEs with matching EPSS scores, divided by all KEV CVEs |
| M04 summary | One population summary | Distribution statistics for the complete EPSS scoring population |
| M04 bands | Five EPSS intervals | Counts and percentages across the complete scored population |
| M05 bands | Five scored intervals plus one unscored category | KEV cohort distribution with explicit all-KEV, scored-KEV, and full-EPSS denominators |

The scored KEV cohort is a subset of the complete EPSS population. The unscored KEV category is not an EPSS probability of zero.

The default v1 export includes M03 and M04. Opt-in v2 adds M05. See [methodology](methodology.md) and [v2 export contracts](exports-p51b.md).
