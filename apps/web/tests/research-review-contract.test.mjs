import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateResearchReviewPack} from '../src/research-review-contract.mjs';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/research-review-invented.json', import.meta.url), 'utf8'));
const copy = () => structuredClone(fixture);
const reject = (object, pattern) => assert.throws(() => validateResearchReviewPack(object), pattern);

test('accepts strictly structured invented research example without approval', () => {
  assert.deepEqual(validateResearchReviewPack(copy()), fixture);
});
test('rejects an invented publication approval', () => {
  const p=copy();p.public_release_approved=true;reject(p,/publication status/);
  p.public_release_approved=false;p.publication_scope='public';reject(p,/publication status/);
});
test('rejects datasets with synthetic fixture or unknown schema', () => {
  const p=copy();p.data_kind='synthetic_fixture';reject(p,/contract/);
  p.data_kind='archived_source_snapshots';p.schema_id='experimental';reject(p,/contract/);
});
test('rejects injected risk-ranking or unidentified fields', () => {
  const p=copy();p.risk_score=99;reject(p,/unexpected fields/);
  delete p.risk_score;p.insights[0].predicted_impact='high';reject(p,/unexpected fields/);
});
test('rejects tampered population percentages and denominators', () => {
  const p=copy();p.insights[0].measures[0].share_percent='99.00';reject(p,/does not reconcile/);
  p.insights[0].measures[0].share_percent='41.67';
  p.insights[0].measures[0].population=11;reject(p,/does not reconcile/);
});
test('rejects modified source order or unknown source IDs', () => {
  const p=copy();p.source_snapshots.reverse();reject(p,/ordered KEV and EPSS/);
  p.source_snapshots.reverse();p.source_snapshots[0].snapshot_id='not-a-digest';reject(p,/snapshot digest/);
});
test('rejects extra, missing, duplicated or reordered insights', () => {
  const p=copy();p.insights.push(structuredClone(p.insights[0]));reject(p,/exactly three/);
  p.insights.pop();p.insights.reverse();reject(p,/reordered finding/);
});
test('rejects inconsistent coverage or impossible highest-band counts', () => {
  const p=copy();p.insights[1].unmatched_kev_count=1;reject(p,/coverage does not reconcile/);
  p.insights[1].unmatched_kev_count=0;
  p.insights[0].measures[0].count=10;p.insights[0].measures[0].share_percent='83.33';
  reject(p,/highest band cannot exceed/);
});
test('rejects absent source timestamps and altered EPSS thresholds', () => {
  const p=copy();p.source_snapshots[0].source_date='';reject(p,/source timestamp/);
  p.source_snapshots[0].source_date='2099-01-10T12:00:00Z';
  p.insights[2].threshold='EPSS >= 0.050';reject(p,/interval definition/);
});
test('refuses empty or oversized plain-language claims', () => {
  const p=copy();p.insights[0].plain_language='';reject(p,/missing or invalid/);
  p.insights[0].plain_language='x'.repeat(1001);reject(p,/missing or invalid/);
});

test('local reviewer is not imported by the public site entrypoint', () => {
  const main = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
  assert.ok(!main.includes('research-review'));
});
