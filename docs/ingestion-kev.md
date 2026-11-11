# P2.1 / CISA KEV ingestion

**Status:** implementation subject to Windows / CI validation. No EPSS ingestion, dbt models, or Power BI exports yet.

This slice adds the explicit command:

```powershell
uv run --locked python -m patchline ingest --source kev
```

This command uses public HTTPS sources maintained by [CISA](https://github.com/cisagov/kev-data): the catalog JSON and its published draft-07 schema. It performs JSON Schema validation with format checking, CVE uniqueness, declared row count reconciliation, valid dates, and semantic checks. Invalid responses stop before a snapshot is published.

Raw files are written to ignored `data/raw/kev/<catalog-sha256>/` directories. The `manifest.json` records URLs, hashes, byte counts, retrieval timestamp, source release timestamp, catalog version, row count, and validation result. A repeat identical download returns `skipped_existing`. Hash-addressed data is not committed to Git.

A command failure does **not** mean Patchline publishes an empty healthy dataset. Upstream changes can break assumptions; investigate schema changes rather than weakening checks.

**Limitations:** This is raw ingestion only, not DuckDB or analytics. No asset exposure is asserted. `dateAdded` is catalog activity, not exploit onset. The schema is downloaded per run rather than pinned to a historical revision; both bytes are archived together. Fixture tests simulate source formats and are clearly synthetic.

## P2.1B: failure and recovery contract

- Reuse verifies catalog and schema hashes, sizes, URLs, version, row count,
  validation marker and the original UTC retrieval timestamp. A corrupt manifest
  or missing artifact is **not** accepted as a successful snapshot.
- A snapshot is considered complete only after `manifest.json` is published.
  Writes use temporary files and same-directory hard links; an interrupted
  write may leave an incomplete directory, which a subsequent identical
  ingestion can finish only if pre-existing artifact bytes match exactly.
- HTTP failures and timeouts raise `KEVIngestionError` and do not publish a
  manifest. Offline tests inject these failures without live network calls.
- Do not edit a completed raw snapshot or silently delete a damaged archive.
  Keep it for investigation; recover independently from a trusted source and
  document any manual quarantine. This slice does not provide automated repair,
  transaction-wide atomic directory publication, locking across processes, or
  historical schema pinning.
