-- Complete selected EPSS population; never filter this model to KEV members.
-- Probabilities are estimates, not confirmed observations of exploitation.
select
    e.snapshot_id,
    e.cve_id,
    e.score_date,
    e.model_version,
    e.epss,
    e.percentile,
    s.retrieved_at_utc
from {{ source('warehouse', 'raw_epss_daily') }} as e
inner join {{ source('warehouse', 'source_snapshots') }} as s
    on s.source = 'epss' and s.snapshot_id = e.snapshot_id
