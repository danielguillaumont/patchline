# Methodology and interpretive limits

Patchline pairs one selected archived KEV catalog snapshot with one selected FIRST EPSS daily score snapshot. These sources have different populations and dates; the exact paired IDs, source dates, and retrieval timestamps are retained in the warehouse and the validated marts.

- KEV means the CVE was listed in the selected CISA catalog. It does not establish exposure for an organization. `dateAdded` is a catalog event, not the beginning of exploitation.
- EPSS is a model-estimated probability of exploitation activity over a 30-day horizon. It is not an observation of exploitation, a severity score, or proof that a system was compromised. The EPSS score and percentile rank are different measures.
- M03 measures how many selected KEV CVEs have a score in the paired EPSS snapshot. Missing scores remain in the KEV denominator; empty KEV populations yield an undefined percentage (`NULL`).
- M04 includes the complete EPSS scoring population, not just the KEV subset. Its five bands are presentation intervals, not official severity or remediation categories. Score 0.0 is a valid scored value.
- M05 partitions the KEV catalog into the same five M04 score bands plus one category for KEV CVEs without an EPSS score. This category has **no probability interval**. It carries the all-KEV share, but its scored-KEV share and full-EPSS comparison are not applicable (`NULL`).
- The scored KEV group is a subset of the full scored EPSS population. Side-by-side percentages are descriptive, not statistically independent cohorts or a causal comparison.
- Empty populations have zero counts and undefined percentage denominators (`NULL`), never synthetic zero percentages. No imputation is applied.

The offline CI fixture is invented, has 3 KEV CVEs and 4 EPSS scored CVEs, and must never be presented as live intelligence. The exporter publishes only M03/M04 under the versioned v1 contract; M05 is an internal dbt mart pending contract evolution. The export manifest records SHA-256 digests, but integrity checks against the full local files occur in Python, not in the static website.
