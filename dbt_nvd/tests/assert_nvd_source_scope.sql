select query_id
from {{ ref('stg_nvd_query_registry') }}
where contract_version <> 'patchline.nvd-duckdb-query-staging.v1'
   or point_in_time_consistency_verified is distinct from false
   or global_nvd_completeness_attested is distinct from false
   or source_origin_independently_verified is distinct from false
   or organization_asset_exposure_known is distinct from false
   or length(query_id) <> 64
   or length(query_manifest_sha256) <> 64
   or length(normalized_sha256) <> 64
