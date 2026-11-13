import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  canonicalBytes, makeCandidateManifest, validatePublicCandidate,
} from '../scripts/explorer-public-contract.mjs';
import {
  createCandidateBundle, verifyCandidateBundle, seedFile,
} from '../scripts/explorer-public-bundle.mjs';

const seed = () => JSON.parse(readFileSync(seedFile, 'utf8'));
const dir = () => path.join(tmpdir(), `exploit-atlas-ea05b-${randomUUID()}`);
function withBundle(fn) {
  const p = dir();
  try { const result = createCandidateBundle(p); return fn(p, result); }
  finally { rmSync(p, {recursive:true, force:true}); }
}
const patch = (p, filename, mutator) => {
  const target = path.join(p, filename);
  const doc = JSON.parse(readFileSync(target, 'utf8'));
  mutator(doc);
  writeFileSync(target, canonicalBytes(doc));
};

test('review candidate retains exactly three CVE-2099 fictional records', () => {
  const doc = validatePublicCandidate(seed());
  assert.deepEqual(doc.records.map(x=>x.cve_id), ['CVE-2099-0001','CVE-2099-0003','CVE-2099-9999']);
  assert.equal(doc.public_release_approved, false);
});
test('missing EPSS and real zero remain different', () => {
  const doc = seed();
  assert.equal(doc.records[0].epss, 0);
  assert.equal(doc.records[1].epss, null);
});
test('candidate generator creates canonical, repeatable checksums', () => {
  withBundle((p, first)=> {
    assert.equal(first.record_count, 3);
    assert.equal(first.status, 'verified_local_candidate_not_approved_for_publication');
    assert.equal(first.public_release_approved, false);
    assert.deepEqual(verifyCandidateBundle(p), first);
    withBundle((_, second)=> assert.deepEqual(second, first));
  });
});
test('candidate manifest is bound to exact deterministic record bytes', () => {
  withBundle((p)=> {
    const records = readFileSync(path.join(p,'cve-records.json'));
    const manifest = JSON.parse(readFileSync(path.join(p,'candidate-manifest.json'),'utf8'));
    assert.deepEqual(manifest, makeCandidateManifest(records));
    assert.equal(manifest.source_archives_reverified, false);
  });
});
test('cannot overwrite an existing candidate directory', () => withBundle(p=>assert.throws(()=>createCandidateBundle(p), /refusing overwrite/)));
test('rejects writing into a project deployable public directory', () => assert.throws(()=>createCandidateBundle(path.resolve('public/demo/exploit-atlas-ea05b-test')), /direct child/));
test('rejects a directory not marked for EA-05B staging', () => assert.throws(()=>createCandidateBundle(path.join(tmpdir(),'unclassified')), /must start/));
test('rejects real-world-looking 2026 CVE substitution', () => {
  const doc=seed();doc.records[0].cve_id='CVE-2026-0001';
  assert.throws(()=>validatePublicCandidate(doc),/fictional CVE/);
});
test('rejects additional or duplicate CVEs', () => {
  const doc=seed();doc.records.push(doc.records[0]);
  assert.throws(()=>validatePublicCandidate(doc),/record count/);
  const duplicate=seed();duplicate.records[1].cve_id=duplicate.records[0].cve_id;
  assert.throws(()=>validatePublicCandidate(duplicate),/membership/);
});
test('rejects a claimed release approval', () => {
  const doc=seed();doc.public_release_approved=true;
  assert.throws(()=>validatePublicCandidate(doc),/unapproved/);
});
test('rejects an altered data source/provenance claim', () => {
  const doc=seed();doc.provenance='real_nvd_api';
  assert.throws(()=>validatePublicCandidate(doc),/provenance/);
});
test('rejects invented prediction or risk fields', () => {
  const doc=seed();doc.records[0].risk_score=99;
  assert.throws(()=>validatePublicCandidate(doc),/unexpected record fields/);
});
test('rejects imputation of missing EPSS as zero', () => {
  const doc=seed();doc.records[1].epss=0;
  assert.throws(()=>validatePublicCandidate(doc),/missing versus zero/);
});
test('rejects incompatible KEV membership and dates', () => {
  const doc=seed();doc.records[2].kev=true;
  assert.throws(()=>validatePublicCandidate(doc),/KEV presence/);
});
test('rejects nonexistent or extra artifact files', () => withBundle(p => {
  writeFileSync(path.join(p,'secret.json'),'{}');
  assert.throws(()=>verifyCandidateBundle(p),/unexpected\/missing/);
}));
test('rejects modified record even when manifest checksum is recomputed', () => withBundle(p => {
  patch(p,'cve-records.json',d=>{d.records[0].title='Tampered fictional network service';});
  const recordBytes = readFileSync(path.join(p,'cve-records.json'));
  writeFileSync(path.join(p,'candidate-manifest.json'), canonicalBytes(makeCandidateManifest(recordBytes)));
  assert.throws(()=>verifyCandidateBundle(p),/differs from reviewed source seed/);
}));
test('rejects forged manifest release approval', () => withBundle(p => {
  patch(p,'candidate-manifest.json',d=>{d.public_release_approved=true;});
  assert.throws(()=>verifyCandidateBundle(p),/manifest integrity/);
}));
test('rejects changed dates or EPSS model claims', () => {
  const d=seed();d.dates.nvd='2026-12-31';
  assert.throws(()=>validatePublicCandidate(d),/illustrative dates/);
  const e=seed();e.epss_model='real-model';
  assert.throws(()=>validatePublicCandidate(e),/illustrative EPSS model/);
});
