# EA-02C1 — Source-pinned Evidence-to-Insight Pack

## Purpose

Make the already-implemented archived CISA KEV / FIRST EPSS research usable as
plain-English findings without detaching claims from their source populations.
This is the **local contract and research logic** milestone. It is not a browser
feature or publication approval.

## Implementation

`src/patchline/research/insights.py` reuses the existing
`patchline.research.case_study.render_report` reconciliation checks before
building three structured, deterministic findings:

1. **Highest EPSS band (0.500–1.000):** compared shares of the scored KEV
   cohort and full scored EPSS population, with counts and denominators.
2. **Source matching coverage:** scored KEV count versus all KEV records in the
   selected catalog, explicitly distinct from a measure of exploitation.
3. **EPSS ≥ 0.100:** compared shares using the same cutoff and different,
   overlapping populations.

Each finding has a headline derived from numeric values, a short explanation,
why it matters, a next investigation question, and a limitation. A changed
snapshot can change the direction of a comparison: **no fixed headline claims
KEV has a higher share unless the counts support it**.

The root contract is `exploit-atlas.archived-insights.v1`, classifies its input
`archived_source_snapshots`, and always emits `public_release_approved: false`
and `publication_scope: local_review_only`. This module does not know how to
stage content for GitHub Pages and cannot approve publication.

## Use with an existing independently verified local v2 export

Source archives and export bytes stay outside the Git repository. Use a locally
verified **archived-source v2** bundle, not the synthetic Pages fixture.

```powershell
$export = 'C:\absolute\path\to\verified-archived-v2-export'
$output = Join-Path $HOME 'Downloads\ea02c1-archived-insights.json'
$kev = '41c8091ad62d508d6f8906ad5cd26b20efe551f7d51b95ecc8a6981fa640b4ea'
$epss = '1f57c666e70798638d84923302d2d54bc52b3da71e49984bc8f13e22291818e7'

uv run --locked python -m patchline.research.insights create `
  --export $export --output $output --kev-snapshot $kev --epss-snapshot $epss

uv run --locked python -m patchline.research.insights verify `
  --export $export --output $output --kev-snapshot $kev --epss-snapshot $epss
```

`create` refuses to overwrite an existing output, requires an absolute external
path, checks the full export bundle using its existing verifier, and writes
canonical UTF-8 JSON. `verify` is read-only and independently rederives the exact
expected bytes against the same pinned input. Neither command downloads feeds
or makes changes to the site. For a new source pair, provide its **own** pinned
SHA-256 identifiers and verified export instead of reusing this report's IDs.

## Validation

```powershell
uv run --locked pytest tests/test_research_insights.py
uv run --locked pytest
uv run --locked ruff check .
```

Tests use invented in-memory data to check determinism, exact known arithmetic,
source classification and pin failures, changing headline direction, nonzero
versus missing scores, output isolation, no overwrite, and tamper detection.
They do **not** independently verify archived external-source bytes.

## Explicit non-goals

- No public publication of the archived real-data insight pack.
- No change to the approved public fictional CVE Explorer or Pages data policy.
- No claims of current vulnerability conditions, organizational exposure,
  remediation priority, causal effects, or future attacks.
- No AI-generated security advice or change to ingestion or dbt models.

## Next

EA-02C2 should design and implement a **separate, explicitly reviewed release
process** for archived aggregate insight content, preserve the fictional-public
contract, and test readable explanation cards with Playwright. The archived
insight pack must not be placed under `apps/web/public` by hand.
