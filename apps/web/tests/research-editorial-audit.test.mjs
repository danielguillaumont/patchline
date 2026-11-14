import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {canonicalBytes} from '../scripts/research-publication-candidate.mjs';
import {ACKNOWLEDGEMENT, makeLocalEditorialRecord} from '../scripts/research-editorial-review.mjs';
import {
  AUDIT_SCHEMA, reconcileLocalEditorialReviews, writeLocalEditorialAudit,
} from '../scripts/research-editorial-audit.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const preflight = () => ({
  schema_id: 'exploit-atlas.archived-publication-preflight.v1',
  status: 'receipt_metadata_matched_local_review_only',
  data_kind: 'archived_source_snapshots',
  publication_scope: 'not_for_publication',
  public_release_approved: false,
  publishable_artifacts_created: false,
  upstream_feed_authenticity_independently_proven: false,
  evidence_scope: 'matching_local_receipt_metadata_not_archive_reverification',
  human_editorial_approval_required: true,
  insight_sha256: 'a'.repeat(64),
  candidate_sha256: 'b'.repeat(64),
  evidence_receipt_sha256: 'c'.repeat(64),
  export_manifest_sha256: 'd'.repeat(64),
  source_snapshots: [
    {source:'kev',snapshot_id:'e'.repeat(64),source_date:'2099-01-10T12:00:00Z',row_count:12},
    {source:'epss',snapshot_id:'f'.repeat(64),source_date:'2099-01-11T12:00:00Z',row_count:100},
  ],
  insight_ids: ['highest-epss-band', 'epss-coverage', 'epss-at-least-point-one'],
});
const p = () => canonicalBytes(preflight());
const record = (preflightBytes=p(), reviewer='reviewer_one', decision='hold', time='2026-11-13T22:00:00.000Z') =>
  canonicalBytes(makeLocalEditorialRecord(preflightBytes, {
    decision, reviewer, reviewed_at_utc: time,
    note: 'Source scope and caveats examined; retain local review status.',
    acknowledge: ACKNOWLEDGEMENT,
  }));
const pinned = bytes => ({bytes, expected_sha256: sha256(bytes)});
const check = (reviews=[pinned(record())], pf=p()) => reconcileLocalEditorialReviews(pf, reviews);
const temp = fn => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ea02c3-slice5-unit-'));
  try {return fn(dir);} finally {rmSync(dir, {recursive:true, force:true});}
};

test('one valid review makes audit metadata without publication authorization', () => {
  const original = p();
  const bytes = record(original);
  const audit = check([pinned(bytes)], original);
  assert.equal(audit.schema_id,AUDIT_SCHEMA);
  assert.equal(audit.review_count,1);
  assert.equal(audit.preflight_sha256,sha256(original));
  assert.equal(audit.reviewers[0].review_sha256,sha256(bytes));
  assert.equal(audit.consistent_editorial_recommendation,'hold');
  assert.equal(audit.public_release_approved,false);
  assert.equal(audit.publishable_artifacts_created,false);
  assert.equal(audit.reviewer_identity_independently_verified,false);
  assert.equal(audit.upstream_feed_authenticity_independently_proven,false);
  assert.equal(audit.source_archive_verification_performed_by_this_tool,false);
  assert.equal(audit.requires_separate_publication_authorization,true);
});

test('distinct reviewers with the same recommendation produce sorted stable audit', () => {
  const a=record(p(),'zed_reviewer');
  const b=record(p(),'alpha_reviewer');
  const first=check([pinned(a),pinned(b)]);
  const second=check([pinned(b),pinned(a)]);
  assert.deepEqual(first,second);
  assert.deepEqual(first.reviewers.map(x=>x.reviewer_label),['alpha_reviewer','zed_reviewer']);
  assert.equal(first.review_count,2);
});

test('ready for separate release review is never public approval', () => {
  const audit=check([pinned(record(p(),'reviewer_one','ready_for_separate_release_review'))]);
  assert.equal(audit.consistent_editorial_recommendation,'ready_for_separate_release_review');
  assert.equal(audit.public_release_approved,false);
});

test('mismatched recommendation is rejected instead of silently choosing one', () => {
  assert.throws(()=>check([
    pinned(record(p(),'reviewer_one','hold')), pinned(record(p(),'reviewer_two','needs_revision')),
  ]),/conflicting editorial/);
});

test('repeated record is rejected', () => {
  const r=record(); assert.throws(()=>check([pinned(r),pinned(r)]),/duplicate review record/);
});

test('same self-attested reviewer label cannot count twice', () => {
  const r1=record(p(),'reviewer_one','hold','2026-11-13T22:00:00.000Z');
  const r2=record(p(),'reviewer_one','hold','2026-11-13T22:00:01.000Z');
  assert.throws(()=>check([pinned(r1),pinned(r2)]),/same self-attested reviewer/);
});

test('stale review fails against a different freshly supplied preflight digest', () => {
  const original=record(); const mutated=preflight();
  mutated.evidence_receipt_sha256='0'.repeat(64);
  assert.throws(()=>check([pinned(original)],canonicalBytes(mutated)),/differs from the supplied preflight/);
});

test('altered review note or reviewer label cannot pass exact reconstruction', () => {
  for(const [field,value] of [['review_note','Changed note after human review was recorded.'],
    ['reviewer_label','different_user']]) {
    const mutated=JSON.parse(record().toString('utf8')); mutated[field]=value;
    assert.throws(()=>check([{bytes: canonicalBytes(mutated), expected_sha256: sha256(record())}]),/independently retained SHA-256 pin/);
  }
});

test('forged claims, extra risk scores, or changed source digest fail', () => {
  for(const [field,value] of [
    ['public_release_approved',true], ['publishable_artifacts_created',true],
    ['reviewer_identity_independently_verified',true],
    ['source_archive_verification_performed_by_this_tool',true],
    ['insight_sha256','0'.repeat(64)], ['risk_score',99],
  ]) {
    const changed=JSON.parse(record().toString('utf8')); changed[field]=value;
    assert.throws(()=>check([{bytes: canonicalBytes(changed), expected_sha256: sha256(record())}]),/independently retained SHA-256 pin/,field);
  }
});

test('changed whitespace or duplicate JSON key cannot pass canonical byte check',()=>{
  const obj=JSON.parse(record().toString('utf8'));
  assert.throws(()=>check([pinned(Buffer.from(JSON.stringify(obj,null,2)))]),/canonical JSON object/);
  const duplicate=Buffer.from(record().toString('utf8').replace(/^\{/, '{"public_release_approved":true,'));
  assert.throws(()=>check([pinned(duplicate)]),/canonical JSON object/);
});

test('malformed or unsafe preflight fails before writing output',()=>{
  const changed=preflight(); changed.public_release_approved=true;
  assert.throws(()=>check([pinned(record())],canonicalBytes(changed)),/preflight safety status/);
  assert.throws(()=>check([pinned(record())],Buffer.from('{"broken":')),/valid UTF-8 JSON/);
});

test('rejects missing or incorrectly formatted independent digest pins',()=>{
  assert.throws(()=>check([{bytes:record()}]),/separately retained SHA-256 pin/);
  assert.throws(()=>check([{bytes:record(),expected_sha256:'abcdef'}]),/separately retained SHA-256 pin/);
});

test('requires 1..12 valid records, not empty or oversized arrays',()=>{
  assert.throws(()=>check([]),/one to twelve/);
  assert.throws(()=>check(Array(13).fill(pinned(record()))),/one to twelve/);
  assert.throws(()=>check([pinned(Buffer.alloc(0))]),/at most 64 KiB/);
});

test('writes one audit file outside repo without review notes or research bodies',()=>temp(dir=>{
  const pf=path.join(dir,'preflight.json');
  const rv=path.join(dir,'review.json');
  writeFileSync(pf,p()); writeFileSync(rv,record());
  const {output,audit}=writeLocalEditorialAudit(pf,[{path:rv, sha256:sha256(record())}],dir);
  const saved=readFileSync(output);
  assert.deepEqual(JSON.parse(saved.toString('utf8')),JSON.parse(canonicalBytes(audit).toString('utf8')));
  assert.deepEqual(readdirSync(path.dirname(output)),['editorial-audit.json']);
  assert.ok(!saved.toString('utf8').includes('Source scope and caveats examined'));
  assert.equal(audit.public_release_approved,false);
}));

test('conflicting reviews create no audit directory',()=>temp(dir=>{
  const pf=path.join(dir,'preflight.json'), one=path.join(dir,'one.json'), two=path.join(dir,'two.json');
  writeFileSync(pf,p()); writeFileSync(one,record());
  writeFileSync(two,record(p(),'reviewer_two','needs_revision'));
  assert.throws(()=>writeLocalEditorialAudit(pf,[{path:one, sha256:sha256(record())},{path:two, sha256:sha256(record(p(),'reviewer_two','needs_revision'))}],dir),/conflicting editorial/);
  assert.deepEqual(readdirSync(dir).sort(),['one.json','preflight.json','two.json']);
}));

test('rejects duplicate path, relative file, or repository-local output',()=>temp(dir=>{
  const pf=path.join(dir,'preflight.json'),rv=path.join(dir,'review.json');
  writeFileSync(pf,p()); writeFileSync(rv,record());
  assert.throws(()=>writeLocalEditorialAudit(pf,[{path:rv,sha256:sha256(record())},{path:rv,sha256:sha256(record())}],dir),/duplicate input file paths/);
  assert.throws(()=>writeLocalEditorialAudit('preflight.json',[{path:rv,sha256:sha256(record())}],dir),/absolute/);
  assert.throws(()=>writeLocalEditorialAudit(pf,[{path:rv,sha256:sha256(record())}],path.resolve('.')),/outside the repository/);
}));

test('rejects symlink review when supported',t=>temp(dir=>{
  const pf=path.join(dir,'preflight.json'),rv=path.join(dir,'review.json');
  writeFileSync(pf,p()); writeFileSync(rv,record());
  const link=path.join(dir,'linked.json');
  try {symlinkSync(rv,link,'file');}
  catch(err) {if (['EPERM','EACCES','ENOTSUP'].includes(err.code)) {
    t.skip('symlink creation unavailable'); return;
  } throw err;}
  assert.throws(()=>writeLocalEditorialAudit(pf,[{path:link,sha256:sha256(record())}],dir),/symlink rejected/);
}));
