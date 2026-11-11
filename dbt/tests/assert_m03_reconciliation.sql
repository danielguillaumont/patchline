-- M03 numerator, denominator and missing count must reconcile to staging/union.
with expected as (
    select
        count(*) as total,
        count(*) filter (where has_epss_score) as matched,
        count(*) filter (where not has_epss_score) as unmatched
    from {{ ref('int_kev_epss_overlap') }}
    where is_kev
), source_population as (
    select count(*) as total from {{ ref('stg_kev') }}
)
select m.metric_id
from {{ ref('m03_epss_coverage_of_kev') }} m
cross join expected e
cross join source_population s
where m.denominator_total_kev <> e.total
   or m.denominator_total_kev <> s.total
   or m.numerator_matched_kev <> e.matched
   or m.unmatched_kev <> e.unmatched
   or m.numerator_matched_kev + m.unmatched_kev <> m.denominator_total_kev
