select query_id, cve_id
from {{ ref('stg_nvd_cves') }}
where source_page_start_index < 0
   or source_page_record_index < 0
   or source_page_start_index + source_page_record_index <> record_index
   or length(source_page_sha256) <> 64
   or record_index < 0
union all
select query_id, cve_id
from {{ ref('stg_nvd_cves') }}
group by query_id, cve_id
having count(*) > 1
