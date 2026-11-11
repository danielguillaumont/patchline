-- Bounds, edge inclusivity, score quantiles, snapshot provenance, and empty-input semantics.
with selected as (
    select snapshot_id, source_date, model_version, retrieved_at_utc
    from {{ source('warehouse', 'source_snapshots') }}
    where source = 'epss'
), expected as (
    select count(*) as scored,
        min(epss) as minimum,
        max(epss) as maximum,
        avg(epss) as mean_score,
        quantile_cont(epss, 0.25) as p25,
        quantile_cont(epss, 0.50) as median_score,
        quantile_cont(epss, 0.75) as p75,
        quantile_cont(epss, 0.90) as p90,
        count(*) filter (where epss is null) as null_count
    from {{ ref('stg_epss') }}
), invalid_summary as (
    select 1 as invalid
    from {{ ref('m04_epss_population_summary') }} m
    cross join expected e
    cross join selected s
    where m.metric_id <> 'M04'
       or m.epss_snapshot_id is distinct from s.snapshot_id
       or m.epss_source_date is distinct from s.source_date
       or m.epss_model_version is distinct from s.model_version
       or m.epss_retrieved_at_utc is distinct from s.retrieved_at_utc
       or m.scored_cve_count <> e.scored
       or m.null_score_count <> e.null_count
       or m.min_epss is distinct from e.minimum
       or m.max_epss is distinct from e.maximum
       or (m.mean_epss is distinct from e.mean_score)
       or (m.p25_epss is distinct from e.p25)
       or (m.median_epss is distinct from e.median_score)
       or (m.p75_epss is distinct from e.p75)
       or (m.p90_epss is distinct from e.p90)
       or (e.scored > 0 and (m.min_epss < 0 or m.max_epss > 1))
), invalid_bands as (
    select 1 as invalid
    from {{ ref('m04_epss_score_bands') }} b
    cross join selected s
    where b.metric_id <> 'M04'
       or b.epss_snapshot_id is distinct from s.snapshot_id
       or b.epss_source_date is distinct from s.source_date
       or b.epss_model_version is distinct from s.model_version
       or b.epss_retrieved_at_utc is distinct from s.retrieved_at_utc
       or b.lower_bound < 0 or b.upper_bound > 1
       or b.lower_bound >= b.upper_bound
       or b.upper_inclusive <> (b.band_order = 5)
       or b.population_percent < 0 or b.population_percent > 100
)
select * from invalid_summary
union all
select * from invalid_bands
