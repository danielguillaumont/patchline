import test from 'node:test';
import assert from 'node:assert/strict';
import { intelligenceBrief } from '../src/brief-reading.mjs';

const manifest = (data_kind = 'synthetic_fixture') => ({
  data_kind,
  source_snapshots: [
    {source:'kev', source_date:'2026-01-15'},
    {source:'epss', source_date:'2026-01-16'},
  ],
});
const coverage = (total = 3, matched = 2) => ({
  denominator_total_kev:total, numerator_matched_kev:matched, unmatched_kev:total-matched,
});
const population = {scored_cve_count:4};

test('reports source-pair coverage as a count, not a risk score', () => {
  const x = intelligenceBrief(manifest(), coverage(), population);
  assert.equal(x.headline, '2 of 3 KEV records have a matching EPSS score.');
  assert.match(x.why, /not proof of a new attack/);
  assert.doesNotMatch(x.headline, /risk|likely|probability|%/i);
});
test('never presents a synthetic fixture as empirical evidence', () => {
  const x = intelligenceBrief(manifest(), coverage(), population);
  assert.equal(x.classification, 'SYNTHETIC EXAMPLE');
  assert.match(x.scopeNote, /fabricated test records/);
  assert.match(x.scopeNote, /not real-world exploitation trends/);
});
test('dates and classification stay visible in archived mode', () => {
  const x = intelligenceBrief(manifest('archived_source_snapshots'), coverage(), population);
  assert.equal(x.classification, 'HISTORICAL SNAPSHOT');
  assert.match(x.scopeNote, /not a current feed/);
  assert.equal(x.sourceLine, 'KEV 2026-01-15 / EPSS 2026-01-16 / 4 scored EPSS CVEs');
});
test('unmatched records are not described as zero risk', () => {
  const x = intelligenceBrief(manifest(), coverage(), population);
  assert.match(x.unmatchedNote, /1 record has no EPSS match/);
  assert.match(x.unmatchedNote, /not be treated as zero probability/);
});
test('handles fully matched source pairs', () => {
  const x = intelligenceBrief(manifest(), coverage(2,2), population);
  assert.match(x.unmatchedNote, /Every KEV record/);
});
test('handles zero matches without inventing probability', () => {
  const x = intelligenceBrief(manifest(), coverage(3,0), population);
  assert.match(x.headline, /0 of 3/);
  assert.match(x.unmatchedNote, /3 records have no EPSS match/);
});
test('does not claim a percentage when the denominator is zero', () => {
  const x = intelligenceBrief(manifest(), coverage(0,0), {...population, scored_cve_count:0});
  assert.match(x.headline, /No KEV records/);
  assert.match(x.unmatchedNote, /cannot be calculated/);
});
test('rejects inconsistent source-pair counts', () => {
  assert.throws(() => intelligenceBrief(manifest(), {...coverage(),unmatched_kev:2}, population), /reconciled/);
});
test('rejects unclassified input and missing dates', () => {
  assert.throws(() => intelligenceBrief(manifest('unknown'),coverage(),population), /classified/);
  assert.throws(() => intelligenceBrief({data_kind:'synthetic_fixture',source_snapshots:[]},coverage(),population), /source dates/);
});
test('does not infer organizational exposure from public intelligence', () => {
  const x = intelligenceBrief(manifest(), coverage(), population);
  assert.match(x.next,/confirm affected assets, exposure/);
  assert.match(x.next,/cannot identify vulnerabilities in your environment/);
});
