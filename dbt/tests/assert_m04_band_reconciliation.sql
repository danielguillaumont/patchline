-- dbt data tests return zero rows when successful.
-- Check full-population denominator, exactly five bands, and no dropped score.
with expected as (
    select count(*) as scored from {{ ref('stg_epss') }}
), band_totals as (
    select
        count(*) as number_of_bands,
        count(distinct band_order) as distinct_bands,
        sum(cve_count) as summed_count,
        min(denominator_scored_cves) as min_denominator,
        max(denominator_scored_cves) as max_denominator,
        sum(population_percent) as summed_percent,
        count(*) filter (where cve_count < 0) as invalid_counts
    from {{ ref('m04_epss_score_bands') }}
)
select * from band_totals b cross join expected e
where b.number_of_bands <> 5
   or b.distinct_bands <> 5
   or b.summed_count <> e.scored
   or b.min_denominator <> e.scored
   or b.max_denominator <> e.scored
   or b.invalid_counts <> 0
   or (e.scored = 0 and b.summed_percent is not null)
   or (e.scored > 0 and (b.summed_percent is null or abs(b.summed_percent - 100.0) > 0.000000001))
