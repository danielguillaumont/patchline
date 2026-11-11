# Metric dictionary v0.1

Status: definitions only; no real metric values have been computed.

| ID | Metric | Numerator / aggregation | Population / denominator | Time basis | Caveat |
|---|---|---|---|---|---|
| M01 | KEV catalog size | Distinct KEV CVEs | Selected official KEV snapshot | Catalog release | Not all exploited CVEs |
| M02 | KEV additions | Count of KEV CVEs whose `dateAdded` is in period | Selected KEV snapshot | `dateAdded`, month | Catalog activity, not exploitation incidence |
| M03 | EPSS coverage of KEV | KEV CVEs matched to scored CVEs | All distinct KEV CVEs in selected snapshot | Paired KEV snapshot and EPSS `score_date` | Report missing KEV count |
| M04 | EPSS score distribution | Full-population CVE count by documented score band / quantiles | Entire selected EPSS score-date population | EPSS `score_date` | Not KEV-only, preserve precision |
| M05 | Signal overlap | Counts of KEV membership within fixed EPSS bands | Each stated scored band population | Paired source snapshots | Descriptive association, not prediction accuracy |
| M06 | High-EPSS non-KEV watchlist | Count or rows with EPSS >= disclosed threshold and not in selected KEV | Selected scored CVE population | Paired source snapshots | Not proof of exploitation; threshold explicit |
| M07 | KEV vendor concentration | Count of KEV CVEs per CISA vendor label | Selected KEV population | Catalog release | Source vendor naming is not universally normalized |
| M08 | Pipeline quality | Source counts, failures, invalids, freshness, unmatched records | Per-run or per-source according to measure | Ingest/run timestamps | Failed run must not be presented as healthy |

## Required reporting contract

Every released metric must include: stable metric ID, label, unit, numerator/aggregation, denominator/population, relevant date(s), source IDs, filters, null policy, calculation SQL reference, and interpretive caveat.

## Watchlist rule

Define a user-visible threshold with documented operator and scope. The watchlist is an analytical filter only, not a severity score or remediation priority. No proprietary Patchline risk score is permitted in the core release.

## Exploration questions (to answer only with computed results)

1. What is the distribution of EPSS scores in the complete latest scored population?
2. How many currently listed KEV entries have scores on the chosen EPSS date?
3. How are KEV additions distributed by month, and what does that *not* imply?
4. What share of high-EPSS scored CVEs are absent from the selected KEV catalog?

Do not populate findings with guessed statistics.
