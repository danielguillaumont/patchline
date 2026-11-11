-- Validate bounded percent, denominator-zero null policy and paired provenance.
-- Do not round the stored numeric percentage; formatting belongs to consumers.
with selected as (
    select
        max(case when source = 'kev' then snapshot_id end) as kev_id,
        max(case when source = 'epss' then snapshot_id end) as epss_id,
        max(case when source = 'kev' then source_date end) as kev_date,
        max(case when source = 'epss' then source_date end) as epss_date,
        max(case when source = 'epss' then model_version end) as model_version
    from {{ source('warehouse', 'source_snapshots') }}
)
select m.metric_id
from {{ ref('m03_epss_coverage_of_kev') }} m
cross join selected s
where m.metric_id <> 'M03'
   or m.metric_label <> 'EPSS coverage of KEV'
   or m.metric_unit <> 'percent'
   or m.kev_snapshot_id is distinct from s.kev_id
   or m.epss_snapshot_id is distinct from s.epss_id
   or m.kev_catalog_date_released is distinct from s.kev_date
   or m.epss_source_date is distinct from s.epss_date
   or m.epss_model_version is distinct from s.model_version
   or m.numerator_matched_kev < 0
   or m.denominator_total_kev < 0
   or m.unmatched_kev < 0
   or (m.denominator_total_kev = 0 and m.coverage_percent is not null)
   or (m.denominator_total_kev > 0 and (
          m.coverage_percent is null
       or m.coverage_percent < 0
       or m.coverage_percent > 100
       or abs(m.coverage_percent - (100.0 * m.numerator_matched_kev / m.denominator_total_kev)) > 0.000000001
   ))
