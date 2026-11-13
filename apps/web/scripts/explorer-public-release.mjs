// EA-05B2: only an explicitly reviewed, checksum-pinned fictional release may enter Pages.
// The EA-05B1 candidate itself must remain unapproved and is never copied to the site.
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalBytes, sha256, validatePublicCandidate,
} from './explorer-public-contract.mjs';

const webRoot = fileURLToPath(new URL('../', import.meta.url));
const repoRoot = resolve(webRoot, '..', '..');
export const candidatePath = join(webRoot, 'fixtures', 'explorer-public-candidate.v1.json');
export const approvalPath = join(webRoot, 'fixtures', 'explorer-public-approval.v1.json');
export const PINNED_CANDIDATE_SHA256 = '79901457953bcfb1d29999aca7b79e03f0f1005f1ed771a5eba72a976d3f07af';
export const RECORD_FILE = 'cve-records.json';
export const MANIFEST_FILE = 'manifest.json';
export const APPROVAL_SCHEMA = 'exploit-atlas.public-explorer-approval.v1';
export const DATA_SCHEMA = 'exploit-atlas.public-explorer-data.v1';
export const MANIFEST_SCHEMA = 'exploit-atlas.public-explorer-release-manifest.v1';
const PUBLICATION_STATE = 'approved_fictional_examples_only';
const exactly = (item, keys) => item !== null && typeof item === 'object' && !Array.isArray(item) &&
  Object.keys(item).sort().join('|') === [...keys].sort().join('|');
function insist(ok, reason) { if (!ok) throw Error(`EA05B2 release rejected: ${reason}`); }

export function validatedRelease(candidate, approval) {
  validatePublicCandidate(candidate);
  const candidateHash = sha256(canonicalBytes(candidate));
  insist(candidateHash === PINNED_CANDIDATE_SHA256, 'candidate differs from pinned reviewed SHA-256');
  insist(exactly(approval, ['schema_id','candidate_sha256','approved','approved_by','approved_at_utc','review_note']), 'approval fields');
  insist(approval.schema_id === APPROVAL_SCHEMA && approval.candidate_sha256 === candidateHash, 'approval identity');
  insist(typeof approval.approved === 'boolean', 'approval must be boolean');
  if (!approval.approved) {
    insist(approval.approved_by === null && approval.approved_at_utc === null && approval.review_note === null, 'pending approval must not claim review');
    return { enabled: false, candidate_sha256: candidateHash };
  }
  insist(approval.approved_by === 'repository_owner', 'approval requires repository owner review');
  insist(typeof approval.approved_at_utc === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(approval.approved_at_utc) &&
    !Number.isNaN(Date.parse(approval.approved_at_utc)), 'approval UTC timestamp');
  insist(typeof approval.review_note === 'string' && approval.review_note.length >= 24 && approval.review_note.length <= 500, 'specific review note');
  const records = {
    schema_id: DATA_SCHEMA,
    data_kind: 'synthetic_fixture',
    publication_state: PUBLICATION_STATE,
    public_release_approved: true,
    provenance: candidate.provenance,
    scope: candidate.scope,
    dates: candidate.dates,
    epss_model: candidate.epss_model,
    records: candidate.records,
  };
  const dataBytes = canonicalBytes(records);
  const manifest = {
    schema_id: MANIFEST_SCHEMA,
    data_kind: 'synthetic_fixture',
    publication_state: PUBLICATION_STATE,
    public_release_approved: true,
    filename: RECORD_FILE,
    sha256: sha256(dataBytes),
    bytes: dataBytes.length,
    record_count: 3,
    source_candidate_sha256: candidateHash,
    source_archives_reverified: false,
  };
  return { enabled: true, candidate_sha256: candidateHash, dataBytes, manifestBytes: canonicalBytes(manifest), manifest };
}
export function releaseFromRepo() {
  const candidate = JSON.parse(readFileSync(candidatePath, 'utf8'));
  const approval = JSON.parse(readFileSync(approvalPath, 'utf8'));
  return validatedRelease(candidate, approval);
}
export function verifyExplorerDirectory(directory, expected = releaseFromRepo()) {
  insist(expected.enabled, 'publication not approved');
  insist(isAbsolute(directory), 'absolute directory required');
  insist(existsSync(directory) && lstatSync(directory).isDirectory() && !lstatSync(directory).isSymbolicLink(), 'missing or linked directory');
  const actual = readdirSync(directory).sort();
  insist(actual.join('|') === [RECORD_FILE, MANIFEST_FILE].sort().join('|'), 'unexpected or missing Explorer files');
  const files = [RECORD_FILE, MANIFEST_FILE];
  for (const name of files) {
    const file = join(directory, name);
    insist(lstatSync(file).isFile() && !lstatSync(file).isSymbolicLink(), `not a regular file: ${name}`);
  }
  insist(readFileSync(join(directory, RECORD_FILE)).equals(expected.dataBytes), 'record bytes changed');
  insist(readFileSync(join(directory, MANIFEST_FILE)).equals(expected.manifestBytes), 'manifest bytes changed');
  return expected.manifest;
}
function isInside(parent, path) {
  const rel = relative(parent, path);
  return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel));
}
export function stagePublicExplorer(destination, release = releaseFromRepo()) {
  insist(typeof destination === 'string' && isAbsolute(destination), 'explicit absolute destination required');
  const dest = resolve(destination);
  insist(dest === destination, 'destination must be normalized');
  insist(!isInside(repoRoot, dest), 'repository output prohibited');
  insist(!existsSync(dest), 'refusing overwrite');
  insist(!existsSync(dest) && dirname(dest) !== dest && dest.endsWith(`${sep}explorer`), 'destination must end with explorer');
  if (!release.enabled) return { status: 'withheld_pending_review', candidate_sha256: release.candidate_sha256 };
  const parent = dirname(dest);
  insist(existsSync(parent) && lstatSync(parent).isDirectory() && !lstatSync(parent).isSymbolicLink(), 'staging parent missing or linked');
  mkdirSync(dest);
  try {
    writeFileSync(join(dest, RECORD_FILE), release.dataBytes, { flag: 'wx' });
    writeFileSync(join(dest, MANIFEST_FILE), release.manifestBytes, { flag: 'wx' });
    verifyExplorerDirectory(dest, release);
    return { status: 'staged_approved_fictional_demo', candidate_sha256: release.candidate_sha256,
      records_sha256: release.manifest.sha256 };
  } catch (error) {
    rmSync(dest, { recursive: true, force: true });
    throw error;
  }
}
