-- M05 compares the scored KEV subset against the complete EPSS population.
-- The sixth row represents missing EPSS matches, never a zero probability score.
-- Reuse M04 definitions so presentation thresholds cannot silently diverge.
with paired_coverage as (
    select * from {{ ref('m03_epss_coverage_of_kev') }}
), band_reference as (
    select * from {{ ref('m04_epss_score_bands') }}
), matched_kev_per_band as (
    select
        b.band_order,
        count(k.cve_id) as kev_cve_count
    from band_reference b
    left join {{ ref('int_kev_epss_overlap') }} k
        on k.is_kev
       and k.has_epss_score
       and k.epss >= b.lower_bound
       and (k.epss < b.upper_bound or (b.upper_inclusive and k.epss <= b.upper_bound))
    group by b.band_order
), dimensions as (
    select
        b.band_order,
        'scored_band' as cohort_category,
        b.band_label,
        b.lower_bound,
        b.upper_bound,
        b.upper_inclusive,
        c.kev_cve_count,
        b.cve_count as full_epss_band_count,
        b.denominator_scored_cves as full_epss_denominator,
        b.population_percent as full_epss_population_percent
    from band_reference b
    inner join matched_kev_per_band c on b.band_order = c.band_order
    union all
    select
        6,
        'unscored_kev',
        'No matching EPSS score',
        cast(null as double),
        cast(null as double),
        cast(null as boolean),
        p.unmatched_kev,
        cast(null as bigint),
        cast(null as bigint),
        cast(null as double)
    from paired_coverage p
)
select
    'M05' as metric_id,
    'KEV cohort by EPSS score band' as metric_label,
    'CVE count and percent' as metric_unit,
    'All CVEs in the selected KEV snapshot; compare only scored KEV against full EPSS' as population,
    'Five M04 probability intervals plus unmatched KEV CVEs without a corresponding EPSS score' as filter_definition,
    'Unscored KEV is a separate category; undefined percentages remain NULL for empty denominators' as null_policy,
    'KEV confirms catalog inclusion; EPSS estimates exploitation probability, not observed events or risk priority' as caveat,
    p.kev_snapshot_id,
    p.epss_snapshot_id,
    p.kev_catalog_date_released,
    p.epss_source_date,
    p.kev_retrieved_at_utc,
    p.epss_retrieved_at_utc,
    p.epss_model_version,
    d.band_order,
    d.cohort_category,
    d.band_label,
    d.lower_bound,
    d.upper_bound,
    d.upper_inclusive,
    d.kev_cve_count,
    p.denominator_total_kev as denominator_all_kev,
    p.numerator_matched_kev as denominator_scored_kev,
    p.unmatched_kev as unscored_kev,
    case
        when p.denominator_total_kev = 0 then cast(null as double)
        else 100.0 * d.kev_cve_count / p.denominator_total_kev
    end as share_all_kev_percent,
    case
        when d.cohort_category = 'unscored_kev' or p.numerator_matched_kev = 0
            then cast(null as double)
        else 100.0 * d.kev_cve_count / p.numerator_matched_kev
    end as share_scored_kev_percent,
    d.full_epss_band_count,
    d.full_epss_denominator,
    d.full_epss_population_percent
from dimensions d
cross join paired_coverage p
