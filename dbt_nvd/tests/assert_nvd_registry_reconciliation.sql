-- dbt singular tests return failing rows, not booleans.
with cve_counts as (
    select query_id, count(*) as actual_count
    from {{ ref('stg_nvd_cves') }}
    group by query_id
), metric_counts as (
    select query_id, count(*) as actual_count
    from {{ ref('stg_nvd_cvss_metrics') }}
    group by query_id
)
select r.query_id
from {{ ref('stg_nvd_query_registry') }} r
left join cve_counts c on c.query_id = r.query_id
left join metric_counts m on m.query_id = r.query_id
where r.record_count <> coalesce(c.actual_count, 0)
   or r.metric_count <> coalesce(m.actual_count, 0)
   or r.page_count < 0
union all
select c.query_id
from cve_counts c
left join {{ ref('stg_nvd_query_registry') }} r on r.query_id = c.query_id
where r.query_id is null
union all
select m.query_id
from metric_counts m
left join {{ ref('stg_nvd_query_registry') }} r on r.query_id = m.query_id
where r.query_id is null
