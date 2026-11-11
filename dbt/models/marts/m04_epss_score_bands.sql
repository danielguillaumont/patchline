-- M04 exhaustive, mutually exclusive bands over the entire selected EPSS population.
-- Upper boundaries exclusive except the final band, which includes 1.0.
-- Boundary labels and ordering are stable analytical definitions, not priority categories.
with defined_bands as (
    select * from (values
        (1, '0.000 to <0.001', 0.000::double, 0.001::double),
        (2, '0.001 to <0.010', 0.001::double, 0.010::double),
        (3, '0.010 to <0.100', 0.010::double, 0.100::double),
        (4, '0.100 to <0.500', 0.100::double, 0.500::double),
        (5, '0.500 to 1.000 inclusive', 0.500::double, 1.000::double)
    ) as b(band_order, band_label, lower_bound, upper_bound)
),
population as (
    select count(*) as total_scored_cves from {{ ref('stg_epss') }}
),
counts as (
    select
        b.band_order,
        count(e.cve_id) as cve_count
    from defined_bands b
    left join {{ ref('stg_epss') }} e
        on e.epss >= b.lower_bound
       and (e.epss < b.upper_bound or (b.band_order = 5 and e.epss <= b.upper_bound))
    group by b.band_order
),
source_metadata as (
    select snapshot_id, source_date, retrieved_at_utc, model_version
    from {{ source('warehouse', 'source_snapshots') }}
    where source = 'epss'
)
select
    'M04' as metric_id,
    'Full-population EPSS score distribution' as metric_label,
    'CVE count and percent' as metric_unit,
    'All CVEs scored in the selected FIRST EPSS daily snapshot, including non-KEV' as population,
    'Fixed non-overlapping EPSS probability bands; no KEV membership filter' as filter_definition,
    'No imputation; zero-valued probabilities belong to the first band' as null_policy,
    'These bands describe estimated probabilities, not exploitation observations or severity' as caveat,
    s.snapshot_id as epss_snapshot_id,
    s.source_date as epss_source_date,
    s.retrieved_at_utc as epss_retrieved_at_utc,
    s.model_version as epss_model_version,
    b.band_order,
    b.band_label,
    b.lower_bound,
    b.upper_bound,
    (b.band_order = 5) as upper_inclusive,
    c.cve_count,
    p.total_scored_cves as denominator_scored_cves,
    case
        when p.total_scored_cves = 0 then cast(null as double)
        else 100.0 * c.cve_count / p.total_scored_cves
    end as population_percent
from defined_bands b
join counts c on b.band_order = c.band_order
cross join population p
cross join source_metadata s
