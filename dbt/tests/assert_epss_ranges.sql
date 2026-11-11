-- Invalid EPSS probability/percentile or missing model/date fails the run.
select snapshot_id, cve_id, epss, percentile, score_date, model_version
from {{ ref('stg_epss') }}
where epss < 0 or epss > 1 or percentile < 0 or percentile > 1
    or not isfinite(epss) or not isfinite(percentile)
    or score_date is null or model_version is null or trim(model_version) = ''
