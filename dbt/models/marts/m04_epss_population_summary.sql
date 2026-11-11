-- M04 summary: complete selected EPSS scoring population, NOT a KEV-only subset.
-- P25/P50/P75/P90 are quantiles of the EPSS *probability score*, not EPSS percentile rank.
-- Population count remains zero for empty input; other statistics are NULL when empty.
with source_metadata as (
    select snapshot_id, source_date, retrieved_at_utc, model_version
    from {{ source('warehouse', 'source_snapshots') }}
    where source = 'epss'
), distribution as (
    select
        count(*) as scored_cve_count,
        min(epss) as min_epss,
        max(epss) as max_epss,
        avg(epss) as mean_epss,
        quantile_cont(epss, 0.25) as p25_epss,
        quantile_cont(epss, 0.50) as median_epss,
        quantile_cont(epss, 0.75) as p75_epss,
        quantile_cont(epss, 0.90) as p90_epss,
        count(*) filter (where epss is null) as null_score_count
    from {{ ref('stg_epss') }}
)
select
    'M04' as metric_id,
    'Full-population EPSS score distribution' as metric_label,
    'probability and CVE count' as metric_unit,
    'All CVEs scored in the selected FIRST EPSS daily snapshot, including non-KEV' as population,
    'No KEV membership filter; one row per CVE and selected EPSS scoring date' as filter_definition,
    'Missing scores are not scored observations; empty population has NULL quantiles' as null_policy,
    'EPSS probabilities estimate exploitation likelihood; they are not observed exploitation' as caveat,
    s.snapshot_id as epss_snapshot_id,
    s.source_date as epss_source_date,
    s.retrieved_at_utc as epss_retrieved_at_utc,
    s.model_version as epss_model_version,
    d.*
from source_metadata s
cross join distribution d
