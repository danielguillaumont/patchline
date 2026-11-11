-- One row per KEV CVE from the single selected, validated warehouse snapshot.
-- Do not interpret date_added as the date exploitation began.
select
    k.snapshot_id,
    k.cve_id,
    k.date_added,
    k.due_date,
    nullif(trim(k.vendor_project), '') as vendor_project,
    nullif(trim(k.product), '') as product,
    nullif(trim(k.vulnerability_name), '') as vulnerability_name,
    nullif(trim(k.known_ransomware_campaign_use), '') as known_ransomware_campaign_use,
    s.source_date as catalog_date_released,
    s.retrieved_at_utc
from {{ source('warehouse', 'raw_kev_snapshot') }} as k
inner join {{ source('warehouse', 'source_snapshots') }} as s
    on s.source = 'kev' and s.snapshot_id = k.snapshot_id
