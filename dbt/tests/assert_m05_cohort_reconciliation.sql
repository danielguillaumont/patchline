-- Six rows must partition the complete KEV catalog, including missing scores.
with source_counts as (
    select
        count(*) as all_kev,
        count(*) filter (where has_epss_score) as scored_kev,
        count(*) filter (where not has_epss_score) as unscored_kev
    from {{ ref('int_kev_epss_overlap') }}
    where is_kev
), totals as (
    select
        count(*) as rows_seen,
        count(distinct band_order) as unique_orders,
        sum(kev_cve_count) as all_kev_count,
        sum(kev_cve_count) filter (where band_order <= 5) as scored_count,
        sum(kev_cve_count) filter (where band_order = 6) as unmatched_count,
        min(denominator_all_kev) as min_all,
        max(denominator_all_kev) as max_all,
        min(denominator_scored_kev) as min_scored,
        max(denominator_scored_kev) as max_scored,
        sum(share_all_kev_percent) as all_share_total,
        sum(share_scored_kev_percent) as scored_share_total,
        count(*) filter (where kev_cve_count < 0) as negative_count
    from {{ ref('m05_kev_epss_cohort_bands') }}
)
select 1 as failed
from totals t cross join source_counts s
where t.rows_seen <> 6
   or t.unique_orders <> 6
   or t.all_kev_count is distinct from s.all_kev
   or t.scored_count is distinct from s.scored_kev
   or t.unmatched_count is distinct from s.unscored_kev
   or t.min_all is distinct from s.all_kev
   or t.max_all is distinct from s.all_kev
   or t.min_scored is distinct from s.scored_kev
   or t.max_scored is distinct from s.scored_kev
   or t.negative_count <> 0
   or (s.all_kev = 0 and t.all_share_total is not null)
   or (s.all_kev > 0 and (t.all_share_total is null or abs(t.all_share_total - 100.0) > 0.00000001))
   or (s.scored_kev = 0 and t.scored_share_total is not null)
   or (s.scored_kev > 0 and (t.scored_share_total is null or abs(t.scored_share_total - 100.0) > 0.00000001))
