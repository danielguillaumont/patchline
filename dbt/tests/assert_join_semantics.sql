-- Flag/category consistency, probability null policy and paired provenance.
-- An EPSS score of 0 is a valid matched value, not absence.
with pair as (
    select
        max(case when source = 'kev' then snapshot_id end) as kev_id,
        max(case when source = 'epss' then snapshot_id end) as epss_id
    from {{ source('warehouse', 'source_snapshots') }}
)
select j.cve_id, j.join_status
from {{ ref('int_kev_epss_overlap') }} j
cross join pair
where j.kev_snapshot_id is distinct from pair.kev_id
   or j.epss_snapshot_id is distinct from pair.epss_id
   or (j.join_status = 'both' and (not j.is_kev or not j.has_epss_score))
   or (j.join_status = 'kev_only' and (not j.is_kev or j.has_epss_score))
   or (j.join_status = 'epss_only' and (j.is_kev or not j.has_epss_score))
   or (j.has_epss_score and (j.epss is null or j.percentile is null
        or j.score_date is null or j.epss_model_version is null
        or j.epss_retrieved_at_utc is null))
   or (not j.has_epss_score and (j.epss is not null or j.percentile is not null
        or j.score_date is not null or j.epss_model_version is not null
        or j.epss_retrieved_at_utc is not null))
   or (j.is_kev and (j.date_added is null or j.catalog_date_released is null
        or j.kev_retrieved_at_utc is null))
   or (not j.is_kev and (j.date_added is not null or j.catalog_date_released is not null
        or j.kev_retrieved_at_utc is not null))
