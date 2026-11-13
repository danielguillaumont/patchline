with counts as (
    select query_id, cve_id, count(*) as metric_count
    from {{ ref('stg_nvd_cvss_metrics') }}
    group by query_id, cve_id
)
select c.query_id, c.cve_id
from {{ ref('stg_nvd_cves') }} c
left join counts m
  on c.query_id = m.query_id and c.cve_id = m.cve_id
where c.missing_cvss_metrics is distinct from (coalesce(m.metric_count, 0) = 0)
