-- Every scored M05 row must use M04's exact thresholds and full-population figures.
with scoring_counts as (
    select
        b.band_order,
        count(k.cve_id) as expected_kev_count
    from {{ ref('m04_epss_score_bands') }} b
    left join {{ ref('int_kev_epss_overlap') }} k
        on k.is_kev and k.has_epss_score
       and k.epss >= b.lower_bound
       and (k.epss < b.upper_bound or (b.upper_inclusive and k.epss <= b.upper_bound))
    group by b.band_order
), invalid_scored as (
    select m.band_order
    from {{ ref('m05_kev_epss_cohort_bands') }} m
    inner join {{ ref('m04_epss_score_bands') }} b on m.band_order = b.band_order
    inner join scoring_counts c on m.band_order = c.band_order
    inner join {{ ref('m03_epss_coverage_of_kev') }} p on true
    where m.metric_id <> 'M05'
       or m.cohort_category <> 'scored_band'
       or m.band_label is distinct from b.band_label
       or m.lower_bound is distinct from b.lower_bound
       or m.upper_bound is distinct from b.upper_bound
       or m.upper_inclusive is distinct from b.upper_inclusive
       or m.full_epss_band_count is distinct from b.cve_count
       or m.full_epss_denominator is distinct from b.denominator_scored_cves
       or m.full_epss_population_percent is distinct from b.population_percent
       or m.kev_cve_count is distinct from c.expected_kev_count
       or m.kev_snapshot_id is distinct from p.kev_snapshot_id
       or m.epss_snapshot_id is distinct from p.epss_snapshot_id
       or m.kev_catalog_date_released is distinct from p.kev_catalog_date_released
       or m.epss_source_date is distinct from p.epss_source_date
       or m.kev_retrieved_at_utc is distinct from p.kev_retrieved_at_utc
       or m.epss_retrieved_at_utc is distinct from p.epss_retrieved_at_utc
       or m.epss_model_version is distinct from p.epss_model_version
       or (p.denominator_total_kev > 0 and (m.share_all_kev_percent is null
            or abs(m.share_all_kev_percent - 100.0 * m.kev_cve_count / p.denominator_total_kev) > 0.00000001))
       or (p.denominator_total_kev = 0 and m.share_all_kev_percent is not null)
       or (p.numerator_matched_kev > 0 and (m.share_scored_kev_percent is null
            or abs(m.share_scored_kev_percent - 100.0 * m.kev_cve_count / p.numerator_matched_kev) > 0.00000001))
       or (p.numerator_matched_kev = 0 and m.share_scored_kev_percent is not null)
), invalid_unmatched as (
    select m.band_order
    from {{ ref('m05_kev_epss_cohort_bands') }} m
    inner join {{ ref('m03_epss_coverage_of_kev') }} p on true
    where m.band_order = 6
      and (m.metric_id <> 'M05'
       or m.cohort_category <> 'unscored_kev'
       or m.band_label <> 'No matching EPSS score'
       or m.kev_cve_count is distinct from p.unmatched_kev
       or m.lower_bound is not null
       or m.upper_bound is not null
       or m.upper_inclusive is not null
       or m.share_scored_kev_percent is not null
       or m.full_epss_band_count is not null
       or m.full_epss_denominator is not null
       or m.full_epss_population_percent is not null
       or (p.denominator_total_kev = 0 and m.share_all_kev_percent is not null)
       or (p.denominator_total_kev > 0 and (m.share_all_kev_percent is null
            or abs(m.share_all_kev_percent - 100.0 * m.kev_cve_count / p.denominator_total_kev) > 0.00000001)))
)
select * from invalid_scored
union all
select * from invalid_unmatched
