import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertSyntheticV2Manifest, demoJsonNames, parseDemoPort } from '../scripts/demo-guard.mjs';

const marts = [
  'm03_epss_coverage_of_kev',
  'm04_epss_population_summary',
  'm04_epss_score_bands',
  'm05_kev_epss_cohort_bands',
];
const fixture = () => ({
  schema_id: 'patchline.analytics-export.v2',
  data_kind: 'synthetic_fixture',
  artifacts: marts.flatMap(name => ['csv','json','parquet'].map(ext => ({path:`${name}.${ext}`}))),
});

test('accepts complete explicit synthetic v2 artifact grid', () => {
  assert.equal(assertSyntheticV2Manifest(fixture()), true);
  assert.deepEqual(demoJsonNames, ['manifest.json', ...marts.map(m => `${m}.json`)]);
});
test('rejects v1 and archived real data', () => {
  assert.throws(() => assertSyntheticV2Manifest({...fixture(),schema_id:'patchline.analytics-export.v1'}), /v2/);
  assert.throws(() => assertSyntheticV2Manifest({...fixture(),data_kind:'archived_source_snapshots'}), /synthetic_fixture/);
});
test('rejects incomplete or duplicate artifact grid', () => {
  const incomplete = fixture(); incomplete.artifacts.pop();
  assert.throws(() => assertSyntheticV2Manifest(incomplete), /twelve/);
  const duplicate = fixture(); duplicate.artifacts[0].path = duplicate.artifacts[1].path;
  assert.throws(() => assertSyntheticV2Manifest(duplicate), /duplicate/);
});
test('rejects traversal and unexpected artifact paths', () => {
  const invalid = fixture(); invalid.artifacts[0].path = '../secrets.csv';
  assert.throws(() => assertSyntheticV2Manifest(invalid), /artifact paths/);
});
test('validates port boundaries', () => {
  assert.equal(parseDemoPort('5173'), 5173);
  assert.equal(parseDemoPort('65535'), 65535);
  for (const invalid of ['0','80','65536','abc','5173.5']) {
    assert.throws(() => parseDemoPort(invalid), /port/);
  }
});
