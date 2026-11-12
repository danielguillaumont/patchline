# Patchline architecture

Patchline is a local-first, archived-data analytics pipeline with a static React frontend. Data sources are public; source versions and retrieval metadata are pinned locally, and all claims are tied to those snapshots rather than to today's changing feeds.

```text
CISA KEV JSON / FIRST EPSS daily CSV
    Python ingestion, shape validation, provenance
       DuckDB raw snapshots + source registry
            dbt staging views
            full CVE-universe outer join
    M03 coverage / M04 full EPSS / M05 KEV cohort bands
              |
       Versioned M03/M04 analytical exports
      JSON, CSV, Parquet + manifest and hashes
              |
       Spectral Index static React application
```

The v1 export contract contains three aggregate models and nine data files. M05 is currently a validated dbt view only, awaiting a new export contract. Spectral Index consumes only verified, deliberately published aggregate JSON plus a manifest. Its fixture demo is classified as synthetic, and the browser does not claim to verify original artifact bytes.

Python, dbt, and frontend code have dedicated GitHub Actions checks; the browser suite runs Chromium against an isolated synthetic warehouse, not a live external service. See [M05 analysis](dbt-p51-m05.md), [export contract](exports-p34.md), and [frontend testing](frontend-p41b3.md).

Current limits: no continuously refreshed feed, no live website API, no CVE-level published explorer, and no completed Power BI artifact in this repository. See the README for reproducible offline commands.
