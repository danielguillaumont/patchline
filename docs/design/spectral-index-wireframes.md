# Spectral Index: visual direction and wireframe contract

Status: design brief / wireframe descriptions, not a shipped frontend. Three final desktop wireframes and mobile treatments are required before visual implementation.

## Design tokens (approved direction)

| Token | Value | Use |
|---|---|---|
| Ink | `#302040` | Headings and primary copy |
| Ultraviolet | `#7055D9` | Interaction and chart focus |
| Citron | `#DDEC7E` | Selected emphasis, never small text on light surface |
| Coral | `#FF705B` | Restrained annotation |
| Paper | `#F3F0FA` | Main canvas |
| White | `#FFFFFF` | Reading/chart surfaces |
| Muted | `#695A76` | Secondary labels, check contrast |

Typography: Archivo (large editorial headings), Instrument Sans (interface and prose), IBM Plex Mono (CVEs, timestamps, units). Verify font licensing and loading; provide fallback faces.

No default cyber-dashboard navy/teal, shield icons, terminal effects, glowing cards, or borrowed Dribbble assets. Original splice motif: two data pathways joining at a deliberate node.

## Screen A — Intelligence Atlas (desktop 1440px)

- Editorial masthead: Patchline identity, three-section navigation, prominent data-as-of and source metadata.
- Asymmetric hero: large question/headline on the left, one carefully contextualized finding with citations on the right.
- Primary visual: generous full-width KEV additions timeline, explicit y-axis, accessible annotated events.
- Secondary visual: full-population EPSS distribution, separate from KEV-limited breakdowns.
- Analysis notes: concise interpretation plus clear caveat panel; no fake urgency labels.

## Screen B — Vulnerability Explorer (desktop 1440px)

- Search CVE input, KEV filter, EPSS band/threshold, sort, and visible selected snapshot metadata.
- Table with keyboard-accessible headings, stable sort, explicit result count and empty state.
- Detail panel: CVE, score + percentile + model/date, KEV membership, nullable official KEV fields, official source links, explanation of signal limits.
- Label the interactive list as a **curated subset**; full-population aggregates remain sourced from the complete warehouse.

## Screen C — Methods & Data Quality (desktop 1440px)

- Top-line source/snapshot manifest with URLs, UTC retrieval and source dates, model version, sha256, row counts.
- Process lineage: KEV + EPSS -> archive -> validate -> DuckDB -> dbt -> validated exports -> site / Power BI.
- QA summary: uniqueness, schema, range, reconciliation, coverage, and missing joins; never display `passed` until verified.
- Documentation links and known limitations prominently accessible.

## Responsive review

Create independently composed frames for 1440px, a smaller laptop, tablet (~768px), and small mobile (~375px). On small screens prioritize source/date context and comprehension, not a squeezed dense dashboard. Tables may use explicit horizontal scrolling or a redesigned detail-first view. Check keyboard focus, contrast, reduced motion, and screen reader labels.

## Visual QA gate

Before frontend implementation, deliver three annotated desktop wireframes, corresponding mobile treatments, an original splice SVG, and a review log recording decisions. All final screenshots must use correctly labeled real snapshots or unambiguously marked synthetic fixtures.
