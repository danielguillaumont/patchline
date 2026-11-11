-- M03: fraction of selected CISA KEV CVEs scored on the paired EPSS date.
-- One row per pinned source pair; coverage is completeness, NOT exploitation risk.
-- Retain NULL coverage when the selected KEV population is empty (undefined ratio).
with source_pair as (
    select
        max(case when source = 'kev' then snapshot_id end) as kev_snapshot_id,
        max(case when source = 'epss' then snapshot_id end) as epss_snapshot_id,
        max(case when source = 'kev' then source_date end) as kev_catalog_date_released,
        max(case when source = 'epss' then source_date end) as epss_source_date,
        max(case when source = 'kev' then retrieved_at_utc end) as kev_retrieved_at_utc,
        max(case when source = 'epss' then retrieved_at_utc end) as epss_retrieved_at_utc,
        max(case when source = 'epss' then model_version end) as epss_model_version
    from {{ source('warehouse', 'source_snapshots') }}
), kev_coverage as (
    select
        count(*) as kev_total,
        count(*) filter (where has_epss_score) as kev_matched,
        count(*) filter (where not has_epss_score) as kev_unmatched
    from {{ ref('int_kev_epss_overlap') }}
    where is_kev
)
select
    'M03' as metric_id,
    'EPSS coverage of KEV' as metric_label,
    'percent' as metric_unit,
    'Selected CISA KEV catalog; one CVE per selected KEV snapshot' as population,
    'Exact CVE match to the complete paired EPSS score-date population' as filter_definition,
    'Unmatched KEV CVEs count in denominator; undefined when KEV total is zero' as null_policy,
    'EPSS coverage is not exploit likelihood, severity, or confirmed exploitation' as caveat,
    p.kev_snapshot_id,
    p.epss_snapshot_id,
    p.kev_catalog_date_released,
    p.epss_source_date,
    p.kev_retrieved_at_utc,
    p.epss_retrieved_at_utc,
    p.epss_model_version,
    c.kev_matched as numerator_matched_kev,
    c.kev_total as denominator_total_kev,
    c.kev_unmatched as unmatched_kev,
    case
        when c.kev_total = 0 then cast(null as double)
        else (100.0 * c.kev_matched) / c.kev_total
    end as coverage_percent
from kev_coverage c
cross join source_pair p
