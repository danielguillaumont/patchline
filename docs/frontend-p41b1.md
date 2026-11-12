# P4.1B1: Interactive EPSS Band Inspector

Status: first interaction slice on branch `feat/p41b-evidence-interactions`. The source models, manifest, and exported JSON contracts remain unchanged.

## Behavior

- The five chart columns are native buttons. Select one with a mouse, touch, Tab plus Enter, or Tab plus Space.
- The selected column has a visible active marker and its detail panel shows the exported band label, exact CVE count, full EPSS population denominator, exported population percentage, and source date.
- A zero-count band remains selectable and is explicitly described as zero. An empty EPSS population displays `Not defined` for shares rather than dividing by zero.
- If the source export omits `band_label`, the inspector says the interval was not provided. It never guesses a threshold.
- M04 represents the full scored EPSS population, including non-KEV CVEs. Selecting a band does not imply exploitation, severity, or a list of CVE records.
- The browser performs shape and reconciliation checks from the existing P4.1A consumer guard. Cryptographic verification still belongs to the Python export verifier.

## Verification

From `apps/web`, run `npm test` and `npm run build`. The first command now includes dedicated band-reading tests in addition to the six P4.1A consumer tests. Do not commit `node_modules`, `dist`, or `public/demo`.

Review the Atlas at 1440 x 900, 768 x 1024, 390 x 844, and 320 x 700. Select every band, including zero-count bands. Verify keyboard focus rings, active state, wording, and document-level horizontal overflow. In the Methods view, ensure the same source classification and provenance remain visible. No em dashes should be added to project copy.

## Deferred

Evidence and artifact-level inspection, automated browser capture, and the CVE-level explorer remain separate slices. This slice does not introduce a new model or claim that aggregate exports contain CVE-level rows.
