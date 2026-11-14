/** EA-02C3 Slice 4: record an editorial recommendation, NEVER release approval.
 * Self-attested review of previous local preflight metadata. This module does
 * not validate original source archives and is NOT a publication mechanism.
 */
import {createHash} from 'node:crypto';
import {lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {TextDecoder} from 'node:util';
import {canonicalBytes} from './research-publication-candidate.mjs';

export const EDITORIAL_SCHEMA = 'exploit-atlas.archived-editorial-review.v1';
export const ACKNOWLEDGEMENT = 'I_UNDERSTAND_THIS_DOES_NOT_AUTHORIZE_PUBLICATION';
export const DECISIONS = Object.freeze([
  'hold', 'needs_revision', 'ready_for_separate_release_review',
]);
const PREFLIGHT_SCHEMA = 'exploit-atlas.archived-publication-preflight.v1';
const EXPECTED_KEYS = [
  'candidate_sha256', 'data_kind', 'evidence_receipt_sha256', 'evidence_scope',
  'export_manifest_sha256', 'human_editorial_approval_required', 'insight_ids',
  'insight_sha256', 'public_release_approved', 'publication_scope',
  'publishable_artifacts_created', 'schema_id', 'source_snapshots', 'status',
  'upstream_feed_authenticity_independently_proven',
].sort();
const INSIGHT_IDS = ['highest-epss-band', 'epss-coverage', 'epss-at-least-point-one'];
const MAX_BYTES = 64 * 1024;
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fail = message => {throw Error(`EA-02C3 editorial review rejected: ${message}`);};
const sha256 = raw => createHash('sha256').update(raw).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const inside = (child, parent) => child === parent || child.startsWith(`${parent}${path.sep}`);
const requireOutside = (resolved, label) => {
  if (inside(resolved.toLowerCase(), repoRoot.toLowerCase())) {
    fail(`${label} must stay outside the repository`);
  }
};
const keysMatch = (obj, expected) => Object.keys(obj).sort().join('|') === expected.join('|');

function canonicalPreflight(raw) {
  if (!Buffer.isBuffer(raw) || !raw.length || raw.length > MAX_BYTES) {
    fail('preflight must be nonempty JSON at most 64 KiB');
  }
  let report;
  try {report = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw));}
  catch {fail('preflight must be valid UTF-8 JSON');}
  if (!report || Array.isArray(report) || typeof report !== 'object' ||
      !canonicalBytes(report).equals(raw)) {
    fail('preflight must have canonical JSON bytes');
  }
  if (!keysMatch(report, EXPECTED_KEYS)) fail('preflight fields are missing or unexpected');
  if (report.schema_id !== PREFLIGHT_SCHEMA ||
      report.status !== 'receipt_metadata_matched_local_review_only' ||
      report.data_kind !== 'archived_source_snapshots' ||
      report.publication_scope !== 'not_for_publication' ||
      report.public_release_approved !== false ||
      report.publishable_artifacts_created !== false ||
      report.upstream_feed_authenticity_independently_proven !== false ||
      report.human_editorial_approval_required !== true ||
      report.evidence_scope !== 'matching_local_receipt_metadata_not_archive_reverification') {
    fail('preflight safety status or evidence scope differs');
  }
  for (const field of [
    'insight_sha256', 'candidate_sha256', 'evidence_receipt_sha256',
    'export_manifest_sha256',
  ]) {
    if (!digest(report[field])) fail(`invalid ${field}`);
  }
  if (!Array.isArray(report.insight_ids) ||
      report.insight_ids.join('|') !== INSIGHT_IDS.join('|')) {
    fail('unexpected insight identity or ordering');
  }
  if (!Array.isArray(report.source_snapshots) || report.source_snapshots.length !== 2 ||
      !['kev','epss'].every((src, i) => {
        const record = report.source_snapshots[i];
        return record && !Array.isArray(record) && typeof record === 'object' &&
          keysMatch(record, ['row_count','snapshot_id','source','source_date']) &&
          record.source === src && digest(record.snapshot_id) &&
          Number.isSafeInteger(record.row_count) && record.row_count >= 0 &&
          typeof record.source_date === 'string' &&
          /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(record.source_date) &&
          Number.isFinite(Date.parse(record.source_date));
      })) {
    fail('invalid source snapshot identities');
  }
  return report;
}

/** Validate self-attestation, preserve a nonpublishing decision, bind exact bytes. */
export function makeLocalEditorialRecord(preflightBytes, input) {
  const preflight = canonicalPreflight(preflightBytes);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('reviewer inputs required');
  }
  if (!DECISIONS.includes(input.decision)) fail('unsupported editorial decision');
  if (typeof input.reviewer !== 'string' || !/^[a-zA-Z0-9._-]{3,64}$/.test(input.reviewer)) {
    fail('reviewer label must be 3-64 safe characters');
  }
  if (typeof input.note !== 'string' || input.note.trim() !== input.note ||
      input.note.length < 24 || input.note.length > 500 || /[\x00-\x1f\x7f]/.test(input.note)) {
    fail('review note must contain 24-500 printable characters');
  }
  if (input.acknowledge !== ACKNOWLEDGEMENT) fail('explicit nonpublication acknowledgment required');
  if (typeof input.reviewed_at_utc !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(input.reviewed_at_utc) ||
      Number.isNaN(Date.parse(input.reviewed_at_utc)) ||
      new Date(input.reviewed_at_utc).toISOString() !== input.reviewed_at_utc) {
    fail('review timestamp must be exact UTC ISO 8601');
  }
  return {
    schema_id: EDITORIAL_SCHEMA,
    status: 'self_attested_editorial_review_local_only',
    editorial_decision: input.decision,
    review_note: input.note,
    reviewer_label: input.reviewer,
    reviewer_identity_independently_verified: false,
    reviewed_at_utc: input.reviewed_at_utc,
    preflight_sha256: sha256(preflightBytes),
    insight_sha256: preflight.insight_sha256,
    candidate_sha256: preflight.candidate_sha256,
    evidence_receipt_sha256: preflight.evidence_receipt_sha256,
    export_manifest_sha256: preflight.export_manifest_sha256,
    source_snapshots: preflight.source_snapshots,
    insight_ids: preflight.insight_ids,
    source_archive_verification_performed_by_this_tool: false,
    upstream_feed_authenticity_independently_proven: false,
    public_release_approved: false,
    publishable_artifacts_created: false,
    requires_separate_publication_authorization: true,
  };
}

export function writeLocalEditorialRecord(preflightFile, decision, reviewer, note,
                                           acknowledge, outputBase = tmpdir(),
                                           reviewedAtUtc = new Date().toISOString()) {
  if (typeof preflightFile !== 'string' || !path.isAbsolute(preflightFile)) {
    fail('preflight input must be an absolute path');
  }
  if (lstatSync(preflightFile).isSymbolicLink()) fail('symlink input rejected');
  const resolved = realpathSync(preflightFile);
  requireOutside(resolved, 'preflight input');
  const bytes = readFileSync(resolved);
  const record = makeLocalEditorialRecord(bytes, {
    decision, reviewer, note, acknowledge, reviewed_at_utc: reviewedAtUtc,
  });
  const parent = realpathSync(outputBase);
  requireOutside(parent, 'review output');
  const folder = mkdtempSync(path.join(parent, 'exploit-atlas-ea02c3-editorial-'));
  const output = path.join(folder, 'editorial-review.json');
  writeFileSync(output, canonicalBytes(record), {flag: 'wx', mode: 0o600});
  return {output, record};
}

function main(args) {
  if (args.length !== 10 || args[0] !== '--preflight' || args[2] !== '--decision' ||
      args[4] !== '--reviewer' || args[6] !== '--note' || args[8] !== '--acknowledge') {
    fail('usage: node scripts/research-editorial-review.mjs --preflight ABSOLUTE_PATH --decision hold|needs_revision|ready_for_separate_release_review --reviewer LABEL --note "REVIEW NOTE" --acknowledge I_UNDERSTAND_THIS_DOES_NOT_AUTHORIZE_PUBLICATION');
  }
  const {output, record} = writeLocalEditorialRecord(args[1], args[3], args[5], args[7], args[9]);
  process.stdout.write(`${JSON.stringify({
    status: record.status, editorial_decision: record.editorial_decision,
    output, preflight_sha256: record.preflight_sha256,
    public_release_approved: false, publishable_artifacts_created: false,
  }, null, 2)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {main(process.argv.slice(2));}
  catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'Unexpected review error'}\n`);
    process.exitCode = 1;
  }
}
