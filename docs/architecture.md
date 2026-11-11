# Architecture / planned, not yet implemented

CISA KEV JSON + schema / FIRST EPSS bulk CSV.gz
-> Python ingestion and immutable source manifests
-> DuckDB -> dbt staging and marts
-> validated versioned exports -> React static site + Power BI Desktop.

**Current P1 implementation:** CLI, offline synthetic fixture, smoke tests, CI configuration. No pipeline stages or source ingestion are implemented.
