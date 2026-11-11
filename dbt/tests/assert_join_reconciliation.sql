-- All selected CVEs must survive the full outer join exactly once.
with expected as (
    select cve_id from {{ ref('stg_kev') }}
    union
    select cve_id from {{ ref('stg_epss') }}
), actual as (
    select cve_id from {{ ref('int_kev_epss_overlap') }}
), missing as (
    select cve_id from expected
    except
    select cve_id from actual
), extra as (
    select cve_id from actual
    except
    select cve_id from expected
)
select 'missing' as issue, cve_id from missing
union all
select 'extra' as issue, cve_id from extra
