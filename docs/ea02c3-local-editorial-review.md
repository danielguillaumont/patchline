# EA-02C3 Slice 4 — Local editorial review record

This checkpoint adds a **human-entered, self-attested review record** for an already verified and metadata-matched historical KEV/EPSS preflight. It is an editorial recommendation checkpoint, **not** permission to publish and **not** an approval mechanism.

## Rules

- A canonical local preflight is required; the original source archive verification must still be freshly run using the Python tool. This Node module only checks the shape of previous *metadata*, not the original archived feed or authenticity of the reviewer.
- A reviewer supplies a specific 24–500-character review note and an explicit nonpublication acknowledgment. Reviewer identity is a self-reported label, not independently authenticated.
- Allowed decisions: `hold`, `needs_revision`, or `ready_for_separate_release_review`. Even the third decision **does not authorize publication**.
- All output records have `public_release_approved: false`, `publishable_artifacts_created: false`, and `requires_separate_publication_authorization: true`.
- Input and output stay outside Git. Only one new local JSON file is written under a new operating-system temporary directory. No historical insight body, individual CVE rows, public assets, or deployment code are written.

## Example (Windows PowerShell 5.1)

Run this only after creating a **fresh** local preflight with `research-publication-preflight.mjs` from the exact November 2026 archive and new Python evidence receipt. Set `$preflight` to that preflight's actual `review-preflight.json` path. Do not use a Git fixture as historical evidence.

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
$preflight = 'C:\path\to\fresh\review-preflight.json'
node .\scripts\research-editorial-review.mjs `
  --preflight $preflight `
  --decision hold `
  --reviewer repository_owner `
  --note 'Reviewed the source scope and caveats; holding for a separate publication review.' `
  --acknowledge I_UNDERSTAND_THIS_DOES_NOT_AUTHORIZE_PUBLICATION
```

The tool writes a metadata-only `editorial-review.json` to Windows TEMP. The reviewer may choose a different supported decision after actually reviewing the archived materials. This script does not prompt for or supply a review statement automatically.

## Tests

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
node --test tests/research-editorial-review.test.mjs
npm test
npm run build
```

Unit tests use invented test metadata only. No public Pages paths, workflow wiring, approval file, or production release schema change in this slice.

## Before any future release

Define a separately reviewed authorization policy with authenticated authorization, explicit public content review, and a deployment-specific gate. Independent upstream-feed authenticity is **not** asserted by any current local artifact. Public archival research is **not** approved in this checkpoint.
