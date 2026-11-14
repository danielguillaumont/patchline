/** EA-02C3: offline, UNAPPROVED historical aggregate review candidate.
 * This never copies the source insights into the repository or a deployable directory.
 * Source archive verification must happen independently before any publication approval.
 */
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {TextDecoder} from 'node:util';
import {validateResearchReviewPack} from '../src/research-review-contract.mjs';

export const CANDIDATE_SCHEMA = 'exploit-atlas.archived-aggregate-publication-candidate.v1';
const MAX_BYTES = 64 * 1024;
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const refuse = (message) => {throw Error(`EA-02C3 candidate rejected: ${message}`);};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const isWithin = (child, parent) => child === parent || child.startsWith(`${parent}${path.sep}`);

function strictInput(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_BYTES) {
    refuse('input must be nonempty JSON of at most 64 KiB');
  }
  let parsed;
  try {parsed = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));}
  catch {refuse('input must contain valid UTF-8 JSON');}
  return validateResearchReviewPack(parsed);
}
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  }
  return value;
}
export function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(stable(value))}\n`, 'utf8');
}

export function makeAggregateCandidate(sourceBytes) {
  const pack = strictInput(sourceBytes);
  return {
    schema_id: CANDIDATE_SCHEMA,
    candidate_status: 'local_review_candidate_only',
    data_kind: 'archived_source_snapshots',
    public_release_approved: false,
    publication_scope: 'not_for_publication',
    browser_contract_validated: true,
    source_archives_reverified_by_this_tool: false,
    source_archive_verification_required: true,
    candidate_contains_research_data: false,
    input_sha256: sha256(sourceBytes),
    input_byte_count: sourceBytes.length,
    source_snapshots: pack.source_snapshots.map(s => ({
      source: s.source, snapshot_id: s.snapshot_id,
      source_date: s.source_date, row_count: s.row_count,
    })),
    insight_ids: pack.insights.map(i => i.id),
    review_requirements: [
      'Independently verify the original 12-artifact v2 source export and insight JSON with the Python CLI.',
      'Review all three aggregate interpretations, denominators, caveats, and exact pinned input bytes.',
      'Obtain a separate explicit human approval before any public publication.',
    ],
  };
}
export function verifyAggregateCandidate(candidate, sourceBytes) {
  const expected = makeAggregateCandidate(sourceBytes);
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) ||
      !canonicalBytes(candidate).equals(canonicalBytes(expected))) {
    refuse('candidate differs from the exact input bytes or required safety status');
  }
  return expected;
}

export function createLocalReviewCandidate(sourcePath, tempBase = tmpdir()) {
  if (typeof sourcePath !== 'string' || !path.isAbsolute(sourcePath)) {
    refuse('source must be an absolute local file path');
  }
  const resolvedSource = realpathSync(sourcePath);
  if (isWithin(resolvedSource.toLowerCase(), repoRoot.toLowerCase())) {
    refuse('do not use files inside the source repository as archived research evidence');
  }
  const bytes = readFileSync(resolvedSource);
  const candidate = makeAggregateCandidate(bytes);
  const outputBase = realpathSync(tempBase);
  if (isWithin(outputBase.toLowerCase(), repoRoot.toLowerCase())) {
    refuse('temporary output cannot be within the source repository');
  }
  const folder = mkdtempSync(path.join(outputBase, 'exploit-atlas-ea02c3-'));
  const manifestPath = path.join(folder, 'candidate-manifest.json');
  writeFileSync(manifestPath, canonicalBytes(candidate), {flag: 'wx', mode: 0o600});
  return {manifestPath, candidate, sourceBytes: bytes.length};
}

function main(argv) {
  if (argv.length !== 2 || argv[0] !== '--input') {
    refuse('usage: node scripts/research-publication-candidate.mjs --input ABSOLUTE_LOCAL_JSON_PATH');
  }
  const {manifestPath, candidate} = createLocalReviewCandidate(argv[1]);
  process.stdout.write(`${JSON.stringify({
    status: candidate.candidate_status,
    input_sha256: candidate.input_sha256,
    output: manifestPath,
    public_release_approved: false,
    source_archives_reverified_by_this_tool: false,
  }, null, 2)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {main(process.argv.slice(2));}
  catch (err) {process.stderr.write(`${err instanceof Error ? err.message : 'Unknown error'}\n`); process.exitCode=1;}
}
