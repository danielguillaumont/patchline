# Warehouse grain, keys, and join policy

Status: conceptual specification. Tables and dbt models are not implemented yet.

| Model | Grain | Key / rule |
|---|---|---|
| `ingestion_runs` | One attempted execution | `run_id`; state, errors, timestamps, source manifests |
| `raw_kev_snapshot` | One CVE per KEV snapshot | `(snapshot_id, cve_id)` |
| `raw_epss_daily` | One CVE per EPSS score date and model | `(score_date, model_version, cve_id)` |
| `stg_kev` | One normalized entry per KEV snapshot | Typed fields; nullable optional values |
| `stg_epss` | One normalized score per date/model | Checked ranges and metadata |
| `dim_cve` | One known CVE | Union of source identifiers; no invented vendor metadata |
| `mart_cve_latest` | One CVE in selected latest EPSS snapshot | Latest score, percentile, current KEV membership, nullable KEV metadata |
| `mart_kev_additions` | Date and optional KEV vendor grouping | Counts of catalog additions, not exploit incidence |
| `mart_epss_distribution` | Selected score date + defined band | Full EPSS scored population aggregates |
| `mart_source_quality` | One source per ingestion run | Checks, count, freshness, join coverage, publication status |

## Join policy

Use normalized complete CVE identifiers. A left join from the **entire selected EPSS scored population** to selected KEV membership preserves non-KEV scored CVEs. Separately count KEV CVEs lacking EPSS. No inner join that silently loses records may be used to define a global population metric.

## Time fields

Keep distinct `downloaded_at_utc`, KEV catalog release date, KEV `dateAdded`, EPSS `score_date`, and export `published_at_utc`. Never infer the source's score date from a local download timestamp.

## Publication invariants

Validation -> transform -> test -> export into temporary files -> validate exported schemas/counts -> atomic publication. A failed run must not overwrite the previously validated release. Each website/BI output includes one traceable source manifest and its snapshot IDs.
