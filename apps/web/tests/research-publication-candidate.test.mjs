import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {
  CANDIDATE_SCHEMA, canonicalBytes, createLocalReviewCandidate,
  makeAggregateCandidate, verifyAggregateCandidate,
} from '../scripts/research-publication-candidate.mjs';

const fixturePath = new URL('./fixtures/research-review-invented.json', import.meta.url);
const valid = () => readFileSync(fixturePath);
const parsed = () => JSON.parse(valid().toString('utf8'));
const reserialize = (obj) => Buffer.from(`${JSON.stringify(obj)}\n`);
const withTmp = (fn) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ea02c3-test-'));
  try {return fn(dir);} finally {rmSync(dir, {recursive:true, force:true});}
};

test('candidate is an unapproved fingerprint, not a copy of research', () => {
  const candidate = makeAggregateCandidate(valid());
  assert.equal(candidate.schema_id, CANDIDATE_SCHEMA);
  assert.equal(candidate.public_release_approved, false);
  assert.equal(candidate.publication_scope, 'not_for_publication');
  assert.equal(candidate.source_archives_reverified_by_this_tool, false);
  assert.equal(candidate.candidate_contains_research_data, false);
  assert.deepEqual(candidate.insight_ids, ['highest-epss-band','epss-coverage','epss-at-least-point-one']);
  assert.ok(!JSON.stringify(candidate).includes('Invented example: highest band comparison'));
  assert.deepEqual(verifyAggregateCandidate(candidate, valid()), candidate);
});

test('repeat runs yield the exact same candidate bytes', () => {
  assert.ok(canonicalBytes(makeAggregateCandidate(valid())).equals(canonicalBytes(makeAggregateCandidate(valid()))));
});

test('changes to raw JSON bytes invalidate the pinned candidate', () => {
  const original = valid();
  const reformatted = Buffer.from(JSON.stringify(JSON.parse(original.toString('utf8')), null, 2));
  const candidate = makeAggregateCandidate(original);
  assert.notEqual(makeAggregateCandidate(reformatted).input_sha256, candidate.input_sha256);
  assert.throws(() => verifyAggregateCandidate(candidate, reformatted), /exact input bytes/);
});

test('altered publication approval or archive verification cannot pass verification', () => {
  const candidate = makeAggregateCandidate(valid());
  assert.throws(() => verifyAggregateCandidate({...candidate, public_release_approved: true}, valid()), /exact input bytes/);
  assert.throws(() => verifyAggregateCandidate({...candidate, source_archives_reverified_by_this_tool: true}, valid()), /exact input bytes/);
  assert.throws(() => verifyAggregateCandidate({...candidate, risk_score: 99}, valid()), /exact input bytes/);
});

test('rejects invalid, empty, oversized and non-UTF-8 source bytes', () => {
  assert.throws(() => makeAggregateCandidate(Buffer.alloc(0)), /nonempty JSON/);
  assert.throws(() => makeAggregateCandidate(Buffer.alloc(65537)), /at most 64 KiB/);
  assert.throws(() => makeAggregateCandidate(Buffer.from([0xff,0xff])), /UTF-8 JSON/);
  assert.throws(() => makeAggregateCandidate(Buffer.from('{')), /UTF-8 JSON/);
});

test('contract refuses forged provenance, unknown prediction and publication claims', () => {
  let doc = parsed(); doc.public_release_approved = true;
  assert.throws(() => makeAggregateCandidate(reserialize(doc)), /publication status/);
  doc = parsed();doc.risk_score = 1;
  assert.throws(() => makeAggregateCandidate(reserialize(doc)), /unexpected fields/);
  doc = parsed();doc.source_snapshots[0].row_count = 1;
  assert.throws(() => makeAggregateCandidate(reserialize(doc)), /coverage does not reconcile|population label or denominator mismatch|percentage does not reconcile/);
});

test('only a separate temp directory gets a manifest, never source data', () => withTmp(dir => {
  const source = path.join(dir, 'archived-insights.json');
  writeFileSync(source, valid());
  const result = createLocalReviewCandidate(source, dir);
  assert.ok(result.manifestPath.startsWith(dir + path.sep));
  assert.deepEqual(readdirSync(path.dirname(result.manifestPath)), ['candidate-manifest.json']);
  assert.deepEqual(JSON.parse(readFileSync(result.manifestPath, 'utf8')), makeAggregateCandidate(valid()));
  assert.equal(result.sourceBytes, valid().length);
}));

test('rejects repo-local research as historical evidence and relative input paths', () => {
  assert.throws(() => createLocalReviewCandidate('./archived.json'), /absolute local file/);
  assert.throws(() => createLocalReviewCandidate(path.resolve('tests/fixtures/research-review-invented.json')), /source repository/);
});
