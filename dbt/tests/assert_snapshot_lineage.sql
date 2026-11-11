-- All modeled rows must match the snapshot IDs and model/date contracts.
with meta as (
    select
        max(case when source = 'kev' then snapshot_id end) as kev_id,
        max(case when source = 'epss' then snapshot_id end) as epss_id,
        max(case when source = 'epss' then substr(source_date, 1, 10) end) as epss_date,
        max(case when source = 'epss' then model_version end) as epss_model
    from {{ source('warehouse', 'source_snapshots') }}
)
select 'kev' as source, k.cve_id
from {{ ref('stg_kev') }} as k cross join meta
where k.snapshot_id <> meta.kev_id
union all
select 'epss' as source, e.cve_id
from {{ ref('stg_epss') }} as e cross join meta
where e.snapshot_id <> meta.epss_id
    or cast(e.score_date as varchar) <> meta.epss_date
    or e.model_version <> meta.epss_model
