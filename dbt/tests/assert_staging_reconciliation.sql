-- Any mismatch is a failing row. Verifies that staging did not lose raw records.
with expected as (
    select source, row_count from {{ source('warehouse', 'source_snapshots') }}
), actual as (
    select 'kev' as source, count(*) as row_count from {{ ref('stg_kev') }}
    union all
    select 'epss' as source, count(*) as row_count from {{ ref('stg_epss') }}
)
select
    expected.source,
    expected.row_count as manifest_rows,
    actual.row_count as staging_rows
from expected
full outer join actual on expected.source = actual.source
where expected.source is null or actual.source is null
    or expected.row_count <> actual.row_count
