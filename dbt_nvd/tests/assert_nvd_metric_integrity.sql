with m as (select * from {{ ref('stg_nvd_cvss_metrics') }}),
     c as (select query_id, cve_id from {{ ref('stg_nvd_cves') }})
select m.query_id, m.cve_id, m.metric_index
from m left join c
  on m.query_id = c.query_id and m.cve_id = c.cve_id
where c.cve_id is null
   or m.metric_index < 0
   or m.base_score < 0
   or m.base_score > 10
   or m.cvss_version not in ('2.0', '3.0', '3.1', '4.0')
union all
select query_id, cve_id, metric_index
from m
group by query_id, cve_id, metric_index
having count(*) > 1
