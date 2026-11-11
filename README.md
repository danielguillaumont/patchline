# PATCHLINE / Vulnerability intelligence. Decision-ready data.

**Status:** P1 foundation (in progress). No live ingestion, warehouse or published report exists yet.

Patchline is a local-first data analytics portfolio project combining **CISA KEV** and **FIRST EPSS** public sources. The intended product is a reproducible Python/DuckDB/dbt pipeline plus Power BI analysis and a bespoke static React site.

## Run offline foundation checks

```powershell
uv sync --python 3.12
uv run python -m patchline --version
uv run python -m patchline doctor --fixture
uv run pytest
uv run ruff check .
```

The fixture doctor validates local sample-data shapes only. **It does not download or validate official feeds.**

## Source attribution

- CISA KEV: https://github.com/cisagov/kev-data
- FIRST EPSS: https://www.first.org/epss/data

## Roadmap

P0 design & metric contracts -> P1 reproducible foundation -> P2 ingestion -> P3 warehouse -> P4 analyst case study -> P5 Power BI -> P6 web atlas -> P7 verified release.

Data limitations and source-date semantics will be recorded in `docs/methodology.md`.
