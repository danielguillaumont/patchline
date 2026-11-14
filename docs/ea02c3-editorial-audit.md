# EA-02C3 Slice 5 — Offline editorial decision audit

This slice verifies that **self-attested local editorial records** remain bound to the **exact, freshly supplied, canonical publication preflight** produced by EA-02C3 Slice 3. It reuses Slice 4's record validation. The resulting summary is **not** a publication approval, a signature, evidence of reviewer identity, proof of upstream authenticity, or a release gate.

## Guarantees and limitations

- Every review must have an **independently retained SHA-256 digest** captured at review creation time. A different digest, stale preflight digest, edited note, modified reviewer label, unexpected field, missing timestamp, or changed classification is rejected. The digest must come from a trustworthy separate record; recalculating the expected hash from a suspect file removes this tamper-detection benefit.
- At most twelve records, at least one, exactly one record per (case-insensitive) self-declared reviewer label. Repeated records or conflicting recommendations fail closed. Reviewers are **self-attested**, not authenticated. Agreement does not imply release approval.
- The preflight must have been regenerated using the archived insight bytes and a newly produced Python evidence-verification receipt. **This script does not perform that re-verification** and cannot establish that upstream feeds were authentic or that independently retained digests are trusted.
- Output is a fresh, **metadata-only** JSON audit file in OS temporary storage. It includes reviewer labels, decision labels, timestamps, and record hashes; it excludes human review notes, CVE rows, insight narratives and source-export data. It refuses inputs, output, and symlinks inside the source repository.
- `public_release_approved` and `publishable_artifacts_created` are always `false`. Even `ready_for_separate_release_review` is strictly an editorial recommendation, not authorization.

## How to use after human review (Windows PowerShell 5.1)

First complete the original independent source verification and preflight. After **you** examine the original research and create an explicit local review using `research-editorial-review.mjs`, immediately calculate its original digest and save it **separately** in your review notes:

```powershell
$review = 'C:\path\to\editorial-review.json'
(Get-FileHash -LiteralPath $review -Algorithm SHA256).Hash.ToLowerInvariant()
```

Later, provide the **saved** hash (do not calculate a new expected hash from a file under suspicion):

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
$preflight = 'C:\path\to\fresh\review-preflight.json'
$review = 'C:\path\to\editorial-review.json'
$savedHash = 'paste-the-64-character-sha256-saved-at-review-time'

node .\scripts\research-editorial-audit.mjs `
  --preflight $preflight `
  --review $review `
  --sha256 $savedHash
```

Add additional pairs of `--review ABSOLUTE_PATH --sha256 SAVED_DIGEST` if independently reviewed records exist. The tool refuses inconsistent decisions instead of selecting an outcome. The output contains *only* an audit summary written outside Git. Never commit raw preflight, review notes, source exports, or historical findings just to make this tool run.

## Tests

```powershell
Set-Location "$HOME\Projects\patchline\apps\web"
node --test .\tests\research-editorial-audit.test.mjs
npm test
npm run build
```

The tests use **invented preflight metadata**; no human review is supplied by the installer or tests. There are no changes to Pages, public Explorer, publication approvals, CI deployment gates, or research publication files.

## Next checkpoint

Before designing a publication release mechanism, define actual reviewer authentication, a separately authorized publication decision, an explicit publishable-content contract, and a deployment-aware release gate. A local checksum is an integrity check relative to a trusted reference, not an authentication signature.
