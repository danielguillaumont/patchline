import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {canonicalBytes} from '../scripts/research-publication-candidate.mjs';
import {
  ACKNOWLEDGEMENT, DECISIONS, EDITORIAL_SCHEMA,
  makeLocalEditorialRecord, writeLocalEditorialRecord,
} from '../scripts/research-editorial-review.mjs';

const sample = () => ({
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
    {source:'kev', snapshot_id:'e'.repeat(64), source_date:'2099-01-10T12:00:00Z', row_count:12},
    {source:'epss', snapshot_id:'f'.repeat(64), source_date:'2099-01-11T12:00:00Z', row_count:100},
  ],
  insight_ids: ['highest-epss-band','epss-coverage','epss-at-least-point-one'],
});
const inputs = () => ({
  decision:'hold', reviewer:'repository_owner',
  note:'Reviewed historical source context; do not publish this material.',
  acknowledge:ACKNOWLEDGEMENT, reviewed_at_utc:'2026-11-13T22:00:00.000Z',
});
const run = (report=sample(), inputsValue=inputs()) =>
  makeLocalEditorialRecord(canonicalBytes(report), inputsValue);
const temp = f => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ea02c3-slice4-test-'));
  try {return f(dir);} finally {rmSync(dir, {recursive:true,force:true});}
};

test('records explicit hold but never approves or publishes', () => {
  const r=run();
  assert.equal(r.schema_id, EDITORIAL_SCHEMA);
  assert.equal(r.status, 'self_attested_editorial_review_local_only');
  assert.equal(r.editorial_decision,'hold');
  assert.equal(r.public_release_approved,false);
  assert.equal(r.publishable_artifacts_created,false);
  assert.equal(r.reviewer_identity_independently_verified,false);
  assert.equal(r.source_archive_verification_performed_by_this_tool,false);
  assert.equal(r.requires_separate_publication_authorization,true);
});

test('all three allowed editorial decisions preserve the release barrier', () => {
  assert.deepEqual(DECISIONS, ['hold','needs_revision','ready_for_separate_release_review']);
  for(const decision of DECISIONS){
    const r=run(sample(),{...inputs(),decision});
    assert.equal(r.public_release_approved,false);
    assert.equal(r.publishable_artifacts_created,false);
  }
});

test('rejects forged public approval or weakened preflight safeguards', () => {
  for(const [field,value] of [
    ['public_release_approved',true],
    ['publishable_artifacts_created',true],
    ['upstream_feed_authenticity_independently_proven',true],
    ['human_editorial_approval_required',false],
    ['publication_scope','public'],
    ['data_kind','synthetic_fixture'],
    ['status','approved'],
  ]) {
    const s=sample(); s[field]=value;
    assert.throws(()=>run(s),/safety status or evidence scope/,field);
  }
});

test('unknown preflight fields including injected risk scores are rejected', () => {
  const s=sample(); s.risk_score=100;
  assert.throws(()=>run(s),/missing or unexpected/);
});

test('wrong digest, insight identities and source IDs reject', () => {
  const s=sample(); s.insight_sha256='123';
  assert.throws(()=>run(s),/invalid insight_sha256/);
  const x=sample(); x.insight_ids=x.insight_ids.reverse();
  assert.throws(()=>run(x),/unexpected insight identity/);
  const y=sample(); y.source_snapshots[1].snapshot_id='not-a-sha';
  assert.throws(()=>run(y),/invalid source snapshot/);
});

test('changed JSON formatting and duplicate keys do not pass byte canonicalization', () => {
  const bytes=Buffer.from(JSON.stringify(sample(), null, 2));
  assert.throws(()=>makeLocalEditorialRecord(bytes, inputs()),/canonical JSON/);
  const duplicate=Buffer.from(canonicalBytes(sample()).toString('utf8').replace(/^\{/, '{"status":"approved",'));
  assert.throws(()=>makeLocalEditorialRecord(duplicate, inputs()),/canonical JSON/);
});

test('explicit acknowledgment is mandatory and cannot be substituted', () => {
  assert.throws(()=>run(sample(),{...inputs(),acknowledge:'approved'}),/acknowledgment/);
  assert.throws(()=>run(sample(),{...inputs(),acknowledge:undefined}),/acknowledgment/);
});

test('no public-approval decision is accepted', () => {
  assert.throws(()=>run(sample(),{...inputs(),decision:'approved'}),/unsupported editorial decision/);
  assert.throws(()=>run(sample(),{...inputs(),decision:'publish'}),/unsupported editorial decision/);
});

test('reviewer and note are validated', () => {
  assert.throws(()=>run(sample(),{...inputs(),reviewer:'<admin>'}),/reviewer label/);
  assert.throws(()=>run(sample(),{...inputs(),note:'too short'}),/review note/);
  assert.throws(()=>run(sample(),{...inputs(),note:'A'.repeat(501)}),/review note/);
  assert.throws(()=>run(sample(),{...inputs(),note:'This review has a line\nbreak and cannot pass.'}),/review note/);
});

test('strict timestamp is required',()=>{
  for(const date of ['2026-11-13','2026-11-13T22:00:00Z','2026-11-13T25:00:00.000Z']){
    assert.throws(()=>run(sample(),{...inputs(),reviewed_at_utc:date}),/UTC ISO 8601/);
  }
});

test('writes one metadata-only JSON file outside repository',()=>temp(dir=>{
  const original=path.join(dir,'preflight.json'); writeFileSync(original,canonicalBytes(sample()));
  const {output,record}=writeLocalEditorialRecord(
    original,'hold','repository_owner',inputs().note,ACKNOWLEDGEMENT,dir,
    inputs().reviewed_at_utc,
  );
  assert.deepEqual(readdirSync(path.dirname(output)),['editorial-review.json']);
  assert.equal(readFileSync(output,'utf8'),canonicalBytes(record).toString('utf8'));
  assert.equal(JSON.stringify(record).includes('Invented example'),false);
  assert.equal(record.public_release_approved,false);
}));

test('invalid acknowledgment fails before creating any output',()=>temp(dir=>{
  const original=path.join(dir,'preflight.json'); writeFileSync(original,canonicalBytes(sample()));
  assert.throws(()=>writeLocalEditorialRecord(
    original,'hold','repository_owner',inputs().note,'approve',dir,inputs().reviewed_at_utc,
  ),/acknowledgment/);
  assert.deepEqual(readdirSync(dir),['preflight.json']);
}));

test('relative input and repository-local input are rejected',()=>temp(dir=>{
  assert.throws(()=>writeLocalEditorialRecord('./p.json','hold','repository_owner',inputs().note,
    ACKNOWLEDGEMENT,dir,inputs().reviewed_at_utc),/absolute path/);
  const localFixture=path.resolve('tests/fixtures/research-review-invented.json');
  assert.throws(()=>writeLocalEditorialRecord(localFixture,'hold','repository_owner',inputs().note,
    ACKNOWLEDGEMENT,dir,inputs().reviewed_at_utc),/outside the repository/);
}));

test('symlinked preflight is rejected when symlinks can be created',t=>temp(dir=>{
  const original=path.join(dir,'preflight.json'); writeFileSync(original,canonicalBytes(sample()));
  const link=path.join(dir,'link.json');
  try {symlinkSync(original,link, 'file');}
  catch (err) {
    if (['EPERM','EACCES','ENOTSUP'].includes(err?.code)) {
      t.skip('Windows symlink creation is not permitted in this environment');
      return;
    }
    throw err;
  }
  assert.throws(()=>writeLocalEditorialRecord(link,'hold','repository_owner',inputs().note,
    ACKNOWLEDGEMENT,dir,inputs().reviewed_at_utc),/symlink/);
}));

test('cannot put output inside repo',()=>temp(dir=>{
  const original=path.join(dir,'preflight.json'); writeFileSync(original,canonicalBytes(sample()));
  assert.throws(()=>writeLocalEditorialRecord(original,'hold','repository_owner',inputs().note,
    ACKNOWLEDGEMENT,path.resolve('.'),inputs().reviewed_at_utc),/outside the repository/);
}));
