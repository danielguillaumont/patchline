// EA-05B1: create/verify local PUBLIC CANDIDATE only. Never writes deployable data.
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalBytes, makeCandidateManifest, sha256, validateCandidateManifest, validatePublicCandidate,
} from './explorer-public-contract.mjs';

export const seedFile = fileURLToPath(new URL('../fixtures/explorer-public-candidate.v1.json', import.meta.url));
const expectedFiles = ['cve-records.json','candidate-manifest.json'];
function insist(ok, reason) { if (!ok) throw Error(`EA05B candidate bundle: ${reason}`); }
function validatedSeed() {
  const seed = JSON.parse(readFileSync(seedFile, 'utf8'));
  return validatePublicCandidate(seed);
}
function safeOutput(out) {
  insist(typeof out === 'string' && out.length > 0, 'explicit --output required');
  const target = path.resolve(out);
  const parent = path.dirname(target);
  insist(parent === path.resolve(tmpdir()), 'output must be a direct child of OS temporary directory');
  insist(/^exploit-atlas-ea05b-[a-zA-Z0-9-]{1,64}$/.test(path.basename(target)), 'output directory must start exploit-atlas-ea05b-');
  insist(!lstatSync(parent).isSymbolicLink(), 'temporary parent symlink not allowed');
  return target;
}
export function createCandidateBundle(output) {
  const dest = safeOutput(output);
  insist(!existsSync(dest), 'output already exists; refusing overwrite');
  const recordBytes = canonicalBytes(validatedSeed());
  const manifestBytes = canonicalBytes(makeCandidateManifest(recordBytes));
  mkdirSync(dest, { recursive: false });
  writeFileSync(path.join(dest, expectedFiles[0]), recordBytes, {flag:'wx'});
  writeFileSync(path.join(dest, expectedFiles[1]), manifestBytes, {flag:'wx'});
  return verifyCandidateBundle(dest);
}
export function verifyCandidateBundle(output) {
  const dest = safeOutput(output);
  insist(existsSync(dest) && lstatSync(dest).isDirectory() && !lstatSync(dest).isSymbolicLink(), 'candidate directory unavailable');
  insist(readdirSync(dest).sort().join('|') === expectedFiles.slice().sort().join('|'), 'unexpected/missing candidate files');
  for (const filename of expectedFiles) insist(lstatSync(path.join(dest, filename)).isFile(), `non-file candidate artifact: ${filename}`);
  const recordBytes = readFileSync(path.join(dest, expectedFiles[0]));
  const manifestBytes = readFileSync(path.join(dest, expectedFiles[1]));
  const record = validatePublicCandidate(JSON.parse(recordBytes.toString('utf8')));
  insist(recordBytes.equals(canonicalBytes(record)), 'noncanonical record bytes');
  const seedBytes = canonicalBytes(validatedSeed());
  insist(recordBytes.equals(seedBytes), 'candidate differs from reviewed source seed');
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  insist(manifestBytes.equals(canonicalBytes(manifest)), 'noncanonical manifest bytes');
  validateCandidateManifest(manifest, recordBytes);
  return {
    schema_id: manifest.schema_id,
    status: 'verified_local_candidate_not_approved_for_publication',
    public_release_approved: false,
    record_count: record.records.length,
    candidate_sha256: sha256(recordBytes),
    manifest_sha256: sha256(manifestBytes),
  };
}
function main(argv) {
  insist(argv.length === 3 && ['create','verify'].includes(argv[0]) && argv[1] === '--output', 'usage: node explorer-public-bundle.mjs create|verify --output <OS-temp/exploit-atlas-ea05b-name>');
  const result = argv[0] === 'create' ? createCandidateBundle(argv[2]) : verifyCandidateBundle(argv[2]);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
