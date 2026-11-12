import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertPublishableManifest } from '../scripts/pages-data.mjs';

const names = ['m03_epss_coverage_of_kev','m04_epss_population_summary','m04_epss_score_bands','m05_kev_epss_cohort_bands'];
const manifest = () => ({
  schema_id: 'patchline.analytics-export.v2',
  data_kind: 'synthetic_fixture',
  source_snapshots: [{source:'kev'},{source:'epss'}],
  artifacts: names.flatMap(model => ['csv','json','parquet'].map(ext => ({path:`${model}.${ext}`}))),
});

test('accepts the exact synthetic v2 publishing boundary', () => {
  assert.equal(assertPublishableManifest(manifest()).artifacts.length, 12);
});

test('rejects archived observations in public build', () => {
  const m = manifest(); m.data_kind = 'archived_source_snapshots';
  assert.throws(() => assertPublishableManifest(m), /synthetic v2/);
});

test('rejects v1 manifests in public build', () => {
  const m = manifest(); m.schema_id = 'patchline.analytics-export.v1';
  assert.throws(() => assertPublishableManifest(m), /synthetic v2/);
});

test('rejects missing, duplicate, or extra export artifacts', () => {
  const missing = manifest(); missing.artifacts.pop();
  const duplicate = manifest(); duplicate.artifacts[1] = duplicate.artifacts[0];
  const extra = manifest(); extra.artifacts[1] = {path:'secret.env'};
  for (const m of [missing, duplicate, extra]) {
    assert.throws(() => assertPublishableManifest(m), /twelve-artifact/);
  }
});

test('rejects altered source lineage', () => {
  const m = manifest(); m.source_snapshots[1].source = 'other';
  assert.throws(() => assertPublishableManifest(m), /fixture lineage/);
});
