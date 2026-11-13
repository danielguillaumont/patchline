select
    query_id,
    cve_id,
    metric_index,
    metric_key,
    cvss_version,
    metric_source,
    metric_type,
    vector_string,
    base_score,
    base_severity,
    source_metric_json
from {{ source('nvd_stage', 'cvss_metrics') }}
