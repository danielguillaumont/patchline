/** EA-02C3 Slice 3: offline publication-contract preflight, NOT a publication gate.
 * Cross-check the archived insight bytes, their pinned candidate and a prior
 * local Python evidence receipt. It neither re-verifies source archives nor
 * authenticates the upstream feeds; never produces publishable research data.
 */
import {createHash} from 'node:crypto';
import {lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {TextDecoder} from 'node:util';
import {
  canonicalBytes, verifyAggregateCandidate,
} from './research-publication-candidate.mjs';

export const PREFLIGHT_SCHEMA = 'exploit-atlas.archived-publication-preflight.v1';
export const RECEIPT_SCHEMA = 'exploit-atlas.archived-evidence-verification-receipt.v1';
const MAX_BYTES = 64 * 1024;
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const receiptKeys = [
  'candidate_sha256', 'data_kind', 'export_artifacts_verified',
  'export_manifest_sha256', 'insight_bytes_independently_rederived',
  'insight_ids', 'insight_sha256', 'public_release_approved',
  'publication_scope', 'schema_id', 'source_snapshots', 'status',
  'upstream_feed_authenticity_independently_proven',
];
const fail = message => {throw Error(`EA-02C3 preflight rejected: ${message}`);};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const within = (child, parent) => child === parent || child.startsWith(`${parent}${path.sep}`);
const isDigest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const same = (a, b) => canonicalBytes(a).equals(canonicalBytes(b));

function parseCanonical(raw, name) {
  if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > MAX_BYTES) {
    fail(`${name} must be nonempty JSON of at most 64 KiB`);
  }
  let value;
  try {value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw));}
  catch {fail(`${name} must be valid UTF-8 JSON`);}
  if (!value || Array.isArray(value) || typeof value !== 'object' ||
      !canonicalBytes(value).equals(raw)) {
    fail(`${name} must have canonical JSON bytes (no duplicate keys or changed formatting)`);
  }
  return value;
}

function checkReceipt(receipt, candidate, insights, candidateBytes) {
  if (Object.keys(receipt).sort().join('|') !== [...receiptKeys].sort().join('|')) {
    fail('evidence receipt has missing or unexpected fields');
  }
  if (receipt.schema_id !== RECEIPT_SCHEMA ||
      receipt.status !== 'verified_local_evidence_only' ||
      receipt.data_kind !== 'archived_source_snapshots' ||
      receipt.publication_scope !== 'offline_review_only' ||
      receipt.public_release_approved !== false ||
      receipt.export_artifacts_verified !== true ||
      receipt.insight_bytes_independently_rederived !== true ||
      receipt.upstream_feed_authenticity_independently_proven !== false) {
    fail('evidence receipt verification status or publication safety fields changed');
  }
  if (!isDigest(receipt.candidate_sha256) ||
      !isDigest(receipt.insight_sha256) || !isDigest(receipt.export_manifest_sha256) ||
      receipt.candidate_sha256 !== sha256(candidateBytes) ||
      receipt.insight_sha256 !== sha256(insights)) {
    fail('receipt digest does not bind the exact candidate and insight bytes');
  }
  if (!same(receipt.source_snapshots, candidate.source_snapshots) ||
      !same(receipt.insight_ids, candidate.insight_ids)) {
    fail('receipt source or insight identity differs from the candidate');
  }
}

/** Validate the record of earlier verification. Do not construe this as verifying the archive anew. */
export function validateHistoricalPreflight(insights, candidateBytes, receiptBytes) {
  if (!Buffer.isBuffer(insights) || insights.length === 0 || insights.length > MAX_BYTES) {
    fail('insight bytes missing or outside 64 KiB limit');
  }
  const candidate = parseCanonical(candidateBytes, 'candidate');
  const receipt = parseCanonical(receiptBytes, 'evidence receipt');
  // Reuse the existing strict browser contract and candidate input identity checks.
  verifyAggregateCandidate(candidate, insights);
  checkReceipt(receipt, candidate, insights, candidateBytes);
  return {
    schema_id: PREFLIGHT_SCHEMA,
    status: 'receipt_metadata_matched_local_review_only',
    data_kind: 'archived_source_snapshots',
    publication_scope: 'not_for_publication',
    public_release_approved: false,
    publishable_artifacts_created: false,
    upstream_feed_authenticity_independently_proven: false,
    evidence_scope: 'matching_local_receipt_metadata_not_archive_reverification',
    human_editorial_approval_required: true,
    insight_sha256: sha256(insights),
    candidate_sha256: sha256(candidateBytes),
    evidence_receipt_sha256: sha256(receiptBytes),
    export_manifest_sha256: receipt.export_manifest_sha256,
    source_snapshots: candidate.source_snapshots,
    insight_ids: candidate.insight_ids,
  };
}

function externalFile(filename) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) fail('input path must be absolute');
  if (lstatSync(filename).isSymbolicLink()) fail('input symlink is not allowed');
  const resolved = realpathSync(filename);
  const parent = repoRoot.toLowerCase();
  if (within(resolved.toLowerCase(), parent)) fail('research inputs may not live inside the repository');
  const bytes = readFileSync(resolved);
  if (bytes.length === 0 || bytes.length > MAX_BYTES) fail('input file size outside 64 KiB limit');
  return bytes;
}

/** Writes metadata only into a new operating-system temp directory; never into Pages. */
export function writeLocalHistoricalPreflight(insightsPath, candidatePath, receiptPath,
                                              outputBase = tmpdir()) {
  const report = validateHistoricalPreflight(
    externalFile(insightsPath), externalFile(candidatePath), externalFile(receiptPath),
  );
  const outputParent = realpathSync(outputBase);
  if (within(outputParent.toLowerCase(), repoRoot.toLowerCase())) {
    fail('preflight output cannot be inside repository');
  }
  const folder = mkdtempSync(path.join(outputParent, 'exploit-atlas-ea02c3-preflight-'));
  const output = path.join(folder, 'review-preflight.json');
  writeFileSync(output, canonicalBytes(report), {flag: 'wx', mode: 0o600});
  return {output, report};
}

function main(args) {
  if (args.length !== 6 || args[0] !== '--insights' ||
      args[2] !== '--candidate' || args[4] !== '--receipt') {
    fail('usage: node scripts/research-publication-preflight.mjs --insights ABSOLUTE_PATH --candidate ABSOLUTE_PATH --receipt ABSOLUTE_PATH');
  }
  const {output, report} = writeLocalHistoricalPreflight(args[1], args[3], args[5]);
  process.stdout.write(`${JSON.stringify({
    status: report.status, output, insight_sha256: report.insight_sha256,
    public_release_approved: false, publishable_artifacts_created: false,
  }, null, 2)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {main(process.argv.slice(2));}
  catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'Unexpected preflight error'}\n`);
    process.exitCode = 1;
  }
}
