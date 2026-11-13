# EA-02A: Intelligence brief, first editorial slice

## Goal

Move the first Exploit Atlas view away from treating a join-coverage percentage as the headline finding. Explain the measure, its source scope, the distinction between known exploitation and future modeled probability, and the need for organization-specific asset context.

## Changes

- Keep the established lavender, purple and citron visual system and existing data charts.
- Rename the first navigation tab to Intelligence brief.
- Make the opening headline and subtitle explain the purpose of the comparison.
- Add a data-driven, plain-language interpretation immediately after the hero.
- Provide visible dataset classification, matched/unmatched counts, source dates, and a path to Methods and Quality.
- Preserve the numerical percentage as a secondary technical coverage measure, not a risk or attack forecast.
- Do not change the analytics export schema, source population, backend, archive files, or existing batch state.

## Truthfulness contract

- Synthetic fixture numbers must never be described as empirical real-world findings.
- KEV membership indicates known exploitation evidence; EPSS estimates future exploitation probability, not observed attacks.
- A missing EPSS match does not imply zero probability.
- Join coverage alone is not organizational security posture or patch urgency.
- Without an asset inventory and exposure details, the app cannot recommend patches for any specific organization.
- Archived source dates must be presented as historical, not live.

## Validation

Run Node unit tests, the full Python suite, Ruff, frontend production build and Pages preview browser tests. A reviewer should be able to answer three questions from the first screen and brief: what is measured, what it means, and what still needs investigation.

## Next slices

EA-02B can refine the chart narratives, introduce contextual glossary explanations, and document a small usability test. EA-02C can add source-backed summary cards for the archived empirical case study in a *separate* reviewed publication pipeline, without replacing the synthetic demo with unlabeled real data.
