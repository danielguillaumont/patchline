# FIRST EPSS source contract (planned)

**Source:** FIRST EPSS data: https://www.first.org/epss/data . Planned bulk input: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz . Attribution: FIRST and Empirical Security.

## Source semantics

The full compressed daily feed covers a CVE-scored population, not merely the KEV subset. `epss` is an estimate of exploitation activity within the documented 30-day horizon, not an organizational compromise probability. `percentile` is a relative ranking, not an additional probability. The EPSS population does not generally supply vendor/product attributes.

## Expected CSV

The current bulk feed is gzip-compressed CSV with `cve`, `epss`, `percentile`, plus comment-style metadata describing score date/model version. Validate the actual header structure and metadata at implementation time; never silently replace missing source dates with download time.

## Validation gates

- Gzip decompresses successfully and CSV has the required columns.
- Metadata is parsed explicitly, including score date and model version; unexpected formats fail clearly.
- Full CVE ID is valid, nonempty and normalized. `epss` and `percentile` are numeric, finite, and within the inclusive [0, 1] interval.
- Key `(score_date, model_version, cve_id)` is unique; duplicate scored CVEs within a daily feed fail validation.
- Numeric source precision is retained, not rounded before storage.
- A zero-row or partially read file is not a successful ingestion.

## Snapshot identity

Store source URL, downloaded-at UTC, SHA-256 over original compressed bytes, byte count, score date, model version, parsed row count, and immutable snapshot ID. Duplicate source hashes must not create duplicate source snapshots.

## Time comparability

Annotate model-version boundaries in historical analysis, and constrain early trend comparisons to the same version. The master build plan records an EPSS v5 publication boundary of 2026-06-15; verify historical metadata when implementing archive analysis.
