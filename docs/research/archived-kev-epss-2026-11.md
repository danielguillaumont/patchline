# Archived KEV and EPSS: a source-pinned cohort comparison

**Classification:** Empirical aggregate analysis of two archived source snapshots. Not a live vulnerability feed.

## Executive reading

- **EPSS match coverage of KEV:** 1,779 of 1,779 KEV CVEs (100.00%). Unmatched KEV: 0.
- **Highest EPSS interval (0.500 to 1.000 inclusive):** 909 of 1,779 scored KEV CVEs (51.10%), compared with 4,382 of 404,864 scored CVEs in the full EPSS population (1.08%).
- **EPSS at or above 0.100:** 1,338 of 1,779 scored KEV CVEs (75.21%) versus 17,541 of 404,864 in the full EPSS population (4.33%).

These percentages describe distributions with **different denominators**. Scored KEV is a subset of the full EPSS population, so the groups are not independent.

## Five-band distribution

| EPSS interval | Full EPSS count (n=404,864) | Full share | Scored KEV count (n=1,779) | Scored KEV share |
| --- | ---: | ---: | ---: | ---: |
| `0.000 to <0.001` | 3,306 | 0.82% | 0 | 0.00% |
| `0.001 to <0.010` | 252,693 | 62.41% | 58 | 3.26% |
| `0.010 to <0.100` | 131,324 | 32.44% | 383 | 21.53% |
| `0.100 to <0.500` | 13,159 | 3.25% | 429 | 24.11% |
| `0.500 to 1.000 inclusive` | 4,382 | 1.08% | 909 | 51.10% |

**Unscored KEV:** 0 of 1,779 (0.00% of all KEV). This is not a probability band and must not be treated as an EPSS score of zero.

## Source provenance

| Field | Archived CISA KEV | Archived FIRST EPSS |
| --- | --- | --- |
| Source date | `2026-11-10T19:03:29.8375Z` | `2026-11-11T12:00:22Z` |
| Snapshot ID (SHA-256) | `41c8091ad62d508d6f8906ad5cd26b20efe551f7d51b95ecc8a6981fa640b4ea` | `1f57c666e70798638d84923302d2d54bc52b3da71e49984bc8f13e22291818e7` |
| Retrieved UTC | `2026-11-11T19:11:54.289300Z` | `2026-11-11T19:36:53.723388Z` |
| Source row count | 1,779 | 404,864 |
| EPSS model version | N/A | `v2026.06.15` |

The verified export uses contract `patchline.analytics-export.v2` with 12 data artifacts, distributed across JSON, CSV and Parquet. The full local bundle was verified against recorded digests before this report was generated.

## Method and limitations

1. Select one archived KEV catalog and one archived EPSS daily score snapshot. Validate the source files and retain their exact snapshot IDs and source dates.
2. Join CVEs by identifier using the Patchline DuckDB and dbt pipeline. M03 records score coverage; M04 records the full scored EPSS population; M05 records the scored KEV cohort and an explicit unscored KEV category.
3. Compare the same five inclusive/exclusive score intervals with the correct denominators. No missing scores are imputed, and no score intervals are renamed.
4. EPSS estimates future exploitation probability over a 30-day horizon. KEV membership indicates known exploitation. Neither measures asset exposure, impact or a company's remediation priority.
5. These archived snapshots have distinct source timestamps. The comparison is descriptive and snapshot-specific, not causal, time-series evidence or a claim about a current vulnerability's exploitability.

## Reproducibility boundary

This report was generated from the immutable, locally verified v2 export bundle. The original data files remain outside Git. The public Spectral Index deployment uses a separate **synthetic fixture**, not these archived measurements.

To reproduce, rebuild the warehouse from the pinned snapshot IDs, run `dbt run` and `dbt test`, create a v2 export, verify the complete export bundle, then run the report generator with the same explicit IDs.
