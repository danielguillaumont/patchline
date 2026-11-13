# EA-02B: chart interpretation and contextual glossary

## Scope

Turn the existing M04 and M05 chart panels into explanations that a first-time reader can understand. Do not change archived source data, demo fixtures, export schemas, Python models, DuckDB, dbt, batch state, or existing chart thresholds.

## Delivered in this slice

- Source-scoped, calculated narrative above the five-band EPSS distribution; the largest interval is selected from validated M04 counts rather than hardcoded.
- A reading of the active M05 interval that reports both denominators, changes with band selection, and explicitly notes the scored KEV subset overlaps the full EPSS population.
- Eight expandable, keyboard-accessible definitions near the charts, without hover-only explanations.
- Explicit classification of synthetic versus archived datasets in all new interpretations.
- Unit tests for valid, empty, and inconsistent data; browser tests at desktop and mobile widths.

## Interpretation boundaries

- EPSS is a model estimate over the next 30 days, not an observed attack rate.
- KEV is evidence of known exploitation, not proof of exposure on a particular asset.
- Population shares indicate distribution, not exploit frequency or remediation urgency.
- Missing scores and zero denominators do not become a probability of zero.
- The scored KEV population is a subset of the scored EPSS population; the displayed groups are not independent.
- The public demo uses fabricated test data. The archived cohort report remains a separate historical publication.

## Manual usability checklist (not yet performed)

Check at 320, 390, 768 and 1440 pixels, with keyboard only and a screen reader when available:

1. Can a new visitor tell that the data is synthetic within 10 seconds?
2. Can they identify the denominator of the full EPSS distribution?
3. Can they explain why scored KEV and all EPSS are overlapping groups?
4. Can they distinguish predicted exploitation probability from known exploitation evidence?
5. Can they expand definitions and select different bands without horizontal page overflow?

Record human observations separately from automated pass/fail results. Do not claim completion of a user study from browser automation alone.
