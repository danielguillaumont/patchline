# Patchline source and metric contracts

Status: design specification, not implemented behavior. These contracts govern subsequent ingestion, DuckDB/dbt modeling, and export work.

- [KEV source contract](kev.md)
- [EPSS source contract](epss.md)
- [Metric definitions](metrics.md)
- [Warehouse grain and joins](warehouse.md)

All claims in the public UI must identify the source snapshot and date. These documents do **not** imply live ingestion exists.

## Implementation gates

1. Validate source formats against current official specifications before accepting live inputs.
2. Preserve original download bytes, SHA-256, source URL, retrieval time, and source date.
3. Reject invalid, duplicate or ambiguous source records before publishing any derived data.
4. Use deterministic, labeled synthetic fixtures for tests; never portray fixture metrics as live evidence.
5. Reconcile all published totals against a single validated warehouse snapshot.
