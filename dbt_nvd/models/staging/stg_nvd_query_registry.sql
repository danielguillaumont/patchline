select
    contract_version,
    query_id,
    query_manifest_sha256,
    normalized_sha256,
    source,
    query_mode,
    record_count,
    metric_count,
    page_count,
    point_in_time_consistency_verified,
    global_nvd_completeness_attested,
    source_origin_independently_verified,
    organization_asset_exposure_known
from {{ source('nvd_stage', 'query_registry') }}
