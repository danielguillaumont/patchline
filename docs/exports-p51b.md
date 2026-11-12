# P5.1B: Versioned M05 analytical exports

P5.1B adds an **opt-in** v2 export contract without changing v1. Both contracts
read the same selected, validated DuckDB snapshot pair after `dbt run` and `dbt test`.

| Contract | Schema ID | Marts | Dataset artifacts | Default? |
| --- | --- | --- | --- | --- |
| v1 | `patchline.analytics-export.v1` | M03, M04 summary, M04 bands | 9 | Yes |
| v2 | `patchline.analytics-export.v2` | All v1 marts plus M05 bands | 12 | No |

In v2, M05 is published as `m05_kev_epss_cohort_bands.csv`, `.json`, and
`.parquet`. It has **six rows**: five mutually exclusive scored EPSS intervals
and one **unscored KEV** row. The sixth row must have null probability bounds,
null scored-cohort share, and null full-EPSS comparisons. The `share_all_kev_percent`
uses the entire KEV denominator, whereas `share_scored_kev_percent` uses the
matched KEV subset. The M04 band distribution refers to the full EPSS population.
These are different denominators and should not be conflated in charts.

## Local offline verification

Run from the repository root after creating and testing all seven dbt models.
Replace the DuckDB database path with your already-built selected warehouse.
Each output directory must be new, and its parent directory must exist.

```powershell
$database = "$env:TEMP\patchline-example.duckdb"  # Replace with your validated DuckDB path
$parent = "$env:TEMP"
uv run --locked python -m patchline.exports.analytics create --database $database --output "$parent\patchline-v1-example"
uv run --locked python -m patchline.exports.analytics verify --output "$parent\patchline-v1-example"
uv run --locked python -m patchline.exports.analytics create --contract v2 --database $database --output "$parent\patchline-v2-example"
uv run --locked python -m patchline.exports.analytics verify --output "$parent\patchline-v2-example"
```

The `verify` command identifies v1 or v2 from the manifest schema ID automatically.
The importer must likewise check `schema_id`, not infer a version from the
number of files. v1 is still the default and is the **only** format currently
accepted by the Spectral Index frontend. P5.1C will introduce an explicit v2
consumer migration rather than silently changing the existing demo.

## Contract integrity and limitations

Creation validates source lineage, M03/M04 reconciliation, and, for v2,
M05 band order, matching M04 intervals, three distinct denominator policies,
percentages, and the separate unscored category. It refuses overwrite and
publishes by staging to an isolated output directory. Verification checks the
contract, exact artifact set, byte counts, SHA-256 hashes, JSON schema and
M05 cross-model reconciliation. Hashes record local integrity only; they do
not provide a signature or prove source authenticity.

`synthetic_fixture` outputs must never be described as empirical or live
vulnerability statistics. No raw CVE-level export, live refresh, network
fetch, or new frontend view is introduced in P5.1B.
