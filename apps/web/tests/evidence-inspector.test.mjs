import test from 'node:test';
import assert from 'node:assert/strict';
import {artifactReading,validateArtifactRegister} from '../src/evidence-inspector.mjs';

const counts={m03_epss_coverage_of_kev:1,m04_epss_population_summary:1,m04_epss_score_bands:5};
const fixtures=()=>Object.entries(counts).flatMap(([model,rows])=>['csv','json','parquet'].map(ext=>({
  path:`${model}.${ext}`,model,rows,bytes:127,sha256:'f'.repeat(64),columns:['metric_id','source_date']
})));
test('accepts exact nine file manifest and preserves metadata',()=>{
  const records=fixtures();
  assert.equal(validateArtifactRegister(records,counts),records);
  assert.deepEqual(artifactReading(records[6]),{modelLabel:'M04 / EPSS bands',formatLabel:'CSV',rowsLabel:'5',bytesLabel:'127',columnsLabel:'metric_id, source_date',digest:'f'.repeat(64)});
});
test('rejects duplicate files and incomplete model-format grid',()=>{
  const records=fixtures();records[1].path=records[0].path;
  assert.throws(()=>validateArtifactRegister(records,counts),/artifact path/);
  assert.throws(()=>validateArtifactRegister(fixtures().slice(1),counts),/nine records/);
});
test('rejects unexpected paths and traversal',()=>{
  const records=fixtures(); records[0].path='../private.csv';
  assert.throws(()=>validateArtifactRegister(records,counts),/artifact path/);
});
test('rejects malformed digest, noninteger bytes, and wrong model',()=>{
  const digest=fixtures(); digest[0].sha256='bad';
  assert.throws(()=>validateArtifactRegister(digest,counts),/digest/);
  const bytes=fixtures(); bytes[0].bytes=-1;
  assert.throws(()=>validateArtifactRegister(bytes,counts),/size/);
  const model=fixtures(); model[0].model='m04_epss_score_bands';
  assert.throws(()=>validateArtifactRegister(model,counts),/model/);
});
test('rejects duplicate column names and incorrect row counts',()=>{
  const cols=fixtures(); cols[0].columns=['metric_id','metric_id'];
  assert.throws(()=>validateArtifactRegister(cols,counts),/column/);
  const rows=fixtures(); rows[8].rows=1;
  assert.throws(()=>validateArtifactRegister(rows,counts),/row count/);
});
test('shows raw manifest digest as recorded metadata, not a verified claim',()=>{
  const entry=fixtures()[0];
  const reading=artifactReading(entry);
  assert.equal(reading.digest,entry.sha256);
  assert.equal(reading.rowsLabel,'1');
});
