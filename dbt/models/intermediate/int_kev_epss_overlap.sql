-- Full CVE universe across one validated KEV snapshot and one EPSS score date.
-- KEV inclusion is a CISA catalog fact; EPSS is a model estimate, not an exploit observation.
-- Each CVE appears once, even when it is absent from one source.
with snapshot_pair as (
    select
        max(case when source = 'kev' then snapshot_id end) as kev_snapshot_id,
        max(case when source = 'epss' then snapshot_id end) as epss_snapshot_id
    from {{ source('warehouse', 'source_snapshots') }}
), combined as (
    select
        coalesce(k.cve_id, e.cve_id) as cve_id,
        (k.cve_id is not null) as is_kev,
        (e.cve_id is not null) as has_epss_score,
        case
            when k.cve_id is not null and e.cve_id is not null then 'both'
            when k.cve_id is not null then 'kev_only'
            else 'epss_only'
        end as join_status,
        k.date_added,
        k.due_date,
        k.vendor_project,
        k.product,
        k.vulnerability_name,
        k.known_ransomware_campaign_use,
        k.catalog_date_released,
        k.retrieved_at_utc as kev_retrieved_at_utc,
        e.score_date,
        e.model_version as epss_model_version,
        e.epss,
        e.percentile,
        e.retrieved_at_utc as epss_retrieved_at_utc,
        k.snapshot_id as matched_kev_snapshot_id,
        e.snapshot_id as matched_epss_snapshot_id
    from {{ ref('stg_kev') }} k
    full outer join {{ ref('stg_epss') }} e on k.cve_id = e.cve_id
)
select
    c.cve_id,
    c.is_kev,
    c.has_epss_score,
    c.join_status,
    pair.kev_snapshot_id,
    pair.epss_snapshot_id,
    c.date_added,
    c.due_date,
    c.vendor_project,
    c.product,
    c.vulnerability_name,
    c.known_ransomware_campaign_use,
    c.catalog_date_released,
    c.kev_retrieved_at_utc,
    c.score_date,
    c.epss_model_version,
    c.epss,
    c.percentile,
    c.epss_retrieved_at_utc
from combined c
cross join snapshot_pair pair
