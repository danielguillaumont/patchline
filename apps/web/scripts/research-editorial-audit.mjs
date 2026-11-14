/** EA-02C3 Slice 5: reconcile self-attested archived editorial review records.
 * This checks exact record-to-preflight bindings; it does not authenticate
 * people or upstream source feeds, reverify the original archive, grant release
 * approval, or write publishable research data.
 */
import {createHash} from 'node:crypto';
import {lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {TextDecoder} from 'node:util';
import {canonicalBytes} from './research-publication-candidate.mjs';
import {ACKNOWLEDGEMENT, makeLocalEditorialRecord} from './research-editorial-review.mjs';

export const AUDIT_SCHEMA = 'exploit-atlas.archived-editorial-audit.v1';
const MAX_BYTES = 64 * 1024;
const MAX_REVIEWS = 12;
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const refuse = message => {throw Error(`EA-02C3 editorial audit rejected: ${message}`);};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const within = (child, parent) => child === parent || child.startsWith(`${parent}${path.sep}`);

function canonicalDocument(raw, label) {
  if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > MAX_BYTES) {
    refuse(`${label} must be nonempty JSON at most 64 KiB`);
  }
  let value;
  try {value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw));}
  catch {refuse(`${label} must be valid UTF-8 JSON`);}
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      !canonicalBytes(value).equals(raw)) {
    refuse(`${label} must be a canonical JSON object`);
  }
  return value;
}

/**
 * Pin each review to an expected SHA-256 retained separately at review time.
 * Reconstruct each record using the existing Slice 4 validator. This checks
 * fields, canonical bytes, timestamps, exact preflight hash, evidence IDs,
 * classification, and all nonpublication invariants. The provided preflight
 * is NOT independently proven fresh or authentic; callers must regenerate it
 * from independently reverified local archived evidence before review.
 */
export function reconcileLocalEditorialReviews(preflightBytes, reviewEntries) {
  canonicalDocument(preflightBytes, 'preflight');
  if (!Array.isArray(reviewEntries) || reviewEntries.length < 1 ||
      reviewEntries.length > MAX_REVIEWS) {
    refuse('one to twelve local editorial records required');
  }
  const reviewers = new Set();
  const decisions = new Set();
  const recordHashes = new Set();
  const details = [];
  for (const [index, entry] of reviewEntries.entries()) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        typeof entry.expected_sha256 !== 'string' ||
        !/^[a-f0-9]{64}$/.test(entry.expected_sha256)) {
      refuse(`review ${index + 1} must supply a separately retained SHA-256 pin`);
    }
    const raw = entry.bytes;
    const digest = sha256(raw);
    if (digest !== entry.expected_sha256) {
      refuse(`review ${index + 1} differs from its independently retained SHA-256 pin`);
    }
    const record = canonicalDocument(raw, `review ${index + 1}`);
    // The actual published v1 record has these exact input names.
    let expected;
    try {
      expected = makeLocalEditorialRecord(preflightBytes, {
        decision: record.editorial_decision,
        reviewer: record.reviewer_label,
        note: record.review_note,
        acknowledge: ACKNOWLEDGEMENT,
        reviewed_at_utc: record.reviewed_at_utc,
      });
    } catch (error) {
      refuse(`review ${index + 1} validation failed: ${error instanceof Error ? error.message : 'invalid record'}`);
    }
    if (!canonicalBytes(expected).equals(raw)) {
      refuse(`review ${index + 1} differs from the supplied preflight or required safety fields`);
    }
    if (recordHashes.has(digest)) refuse('duplicate review record');
    const reviewerKey = record.reviewer_label.toLowerCase();
    if (reviewers.has(reviewerKey)) {
      refuse('same self-attested reviewer label appears more than once');
    }
    recordHashes.add(digest);
    reviewers.add(reviewerKey);
    decisions.add(record.editorial_decision);
    details.push({
      reviewer_label: record.reviewer_label,
      reviewed_at_utc: record.reviewed_at_utc,
      editorial_decision: record.editorial_decision,
      review_sha256: digest,
    });
  }
  if (decisions.size !== 1) refuse('conflicting editorial recommendations; resolve manually');
  details.sort((a, b) => a.reviewer_label.localeCompare(b.reviewer_label, 'en'));
  return {
    schema_id: AUDIT_SCHEMA,
    status: 'local_editorial_records_consistent_not_publication_authorization',
    data_kind: 'archived_source_snapshots',
    preflight_sha256: sha256(preflightBytes),
    review_count: details.length,
    consistent_editorial_recommendation: details[0].editorial_decision,
    reviewers: details,
    reviewer_identity_independently_verified: false,
    upstream_feed_authenticity_independently_proven: false,
    source_archive_verification_performed_by_this_tool: false,
    public_release_approved: false,
    publishable_artifacts_created: false,
    requires_separate_publication_authorization: true,
  };
}

function readExternal(filename, label) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) {
    refuse(`${label} path must be absolute`);
  }
  if (lstatSync(filename).isSymbolicLink()) refuse(`${label} symlink rejected`);
  const resolved = realpathSync(filename);
  if (within(resolved.toLowerCase(), repoRoot.toLowerCase())) {
    refuse(`${label} must stay outside the repository`);
  }
  if (!lstatSync(resolved).isFile()) refuse(`${label} must be a regular file`);
  const bytes = readFileSync(resolved);
  canonicalDocument(bytes, label);
  return {resolved, bytes};
}

/** Writes only a nonpublishing, metadata-only reconciliation in a fresh TEMP dir. */
export function writeLocalEditorialAudit(preflightPath, reviewEntries, outputBase = tmpdir()) {
  if (!Array.isArray(reviewEntries) || reviewEntries.length < 1 ||
      reviewEntries.length > MAX_REVIEWS) {
    refuse('one to twelve review paths required');
  }
  const preflight = readExternal(preflightPath, 'preflight');
  const reviews = reviewEntries.map((entry, i) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      refuse(`review ${i + 1} must include path and SHA-256 pin`);
    }
    return {...readExternal(entry.path, `review ${i + 1}`), expected_sha256: entry.sha256};
  });
  if (new Set([preflight.resolved.toLowerCase(),
    ...reviews.map(r => r.resolved.toLowerCase())]).size !== reviews.length + 1) {
    refuse('duplicate input file paths are not allowed');
  }
  const audit = reconcileLocalEditorialReviews(preflight.bytes,
    reviews.map(r => ({bytes: r.bytes, expected_sha256: r.expected_sha256})));
  if (typeof outputBase !== 'string' || !path.isAbsolute(outputBase)) {
    refuse('output directory must be absolute');
  }
  if (lstatSync(outputBase).isSymbolicLink()) refuse('output directory symlink rejected');
  const resolvedOutput = realpathSync(outputBase);
  if (within(resolvedOutput.toLowerCase(), repoRoot.toLowerCase())) {
    refuse('audit output must stay outside the repository');
  }
  const folder = mkdtempSync(path.join(resolvedOutput, 'exploit-atlas-ea02c3-audit-'));
  const output = path.join(folder, 'editorial-audit.json');
  writeFileSync(output, canonicalBytes(audit), {flag: 'wx', mode: 0o600});
  return {output, audit};
}

function main(args) {
  if (args.length < 6 || (args.length - 2) % 4 !== 0 || args[0] !== '--preflight') {
    refuse('usage: node scripts/research-editorial-audit.mjs --preflight ABS_PATH --review ABS_PATH --sha256 PINNED_SHA256 [--review ABS_PATH --sha256 PINNED_SHA256 ...]');
  }
  const entries = [];
  for (let i = 2; i < args.length; i += 4) {
    if (args[i] !== '--review' || args[i + 2] !== '--sha256') {
      refuse('review must be followed by its separately retained --sha256 pin');
    }
    entries.push({path: args[i + 1], sha256: args[i + 3]});
  }
  const {output, audit} = writeLocalEditorialAudit(args[1], entries);
  process.stdout.write(`${JSON.stringify({
    status: audit.status,
    output,
    review_count: audit.review_count,
    consistent_editorial_recommendation: audit.consistent_editorial_recommendation,
    public_release_approved: false,
    publishable_artifacts_created: false,
  }, null, 2)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {main(process.argv.slice(2));}
  catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'Unexpected audit error'}\n`);
    process.exitCode = 1;
  }
}
