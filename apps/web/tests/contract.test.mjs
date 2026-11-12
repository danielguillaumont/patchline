import test from 'node:test';
import assert from 'node:assert/strict';
import {validateBundle} from '../src/contract.mjs';
const id = 'abcdef';
const mk = () => {
 const sources=[{source:'kev',snapshot_id:'k',source_date:'2026-01-15',row_count:3},{source:'epss',snapshot_id:'e',source_date:'2026-01-15',row_count:4}];
 const models=['m03_epss_coverage_of_kev','m04_epss_population_summary','m04_epss_score_bands'];
 const artifacts=models.flatMap((model,i)=>['csv','json','parquet'].map(ext=>({path:`${model}.${ext}`,model,bytes:100,rows:i===2?5:1,sha256:'a'.repeat(64),columns:['metric_id']})));
 const manifest={schema_id:'patchline.analytics-export.v1',data_kind:'synthetic_fixture',source_snapshots:sources,artifacts,validation:{kev_total:3,kev_matched:2,kev_unmatched:1,epss_scored_total:4}};
 const c=[{metric_id:'M03',denominator_total_kev:3,numerator_matched_kev:2,unmatched_kev:1,coverage_percent:200/3,kev_snapshot_id:'k',epss_snapshot_id:'e',kev_catalog_date_released:'2026-01-15',epss_source_date:'2026-01-15'}];
 const s=[{metric_id:'M04',scored_cve_count:4,epss_snapshot_id:'e',epss_source_date:'2026-01-15',min_epss:0,max_epss:1,mean_epss:.4525,p25_epss:.0075,median_epss:.405,p75_epss:.85,p90_epss:.94}];
 const counts=[1,0,1,0,2]; const b=counts.map((n,i)=>({metric_id:'M04',band_order:i+1,cve_count:n,denominator_scored_cves:4,population_percent:25*n,epss_snapshot_id:'e',epss_source_date:'2026-01-15'}));
 return [manifest,c,s,b];
};
test('accepts reconciled synthetic exports',()=>assert.equal(validateBundle(...mk()).coverage.coverage_percent,200/3));
test('rejects unclassified data',()=>{const x=mk();x[0].data_kind='unknown';assert.throws(()=>validateBundle(...x));});
test('rejects mismatched coverage',()=>{const x=mk();x[1][0].unmatched_kev=0;assert.throws(()=>validateBundle(...x));});
test('rejects mismatched band counts',()=>{const x=mk();x[3][0].cve_count=2;assert.throws(()=>validateBundle(...x));});
test('rejects false source dates',()=>{const x=mk();x[2][0].epss_source_date='bad';assert.throws(()=>validateBundle(...x));});
test('rejects missing datasets',()=>{const x=mk();x[3]=[];assert.throws(()=>validateBundle(...x));});

test('rejects a duplicate manifest artifact path',()=>{const x=mk();x[0].artifacts[0].path=x[0].artifacts[1].path;assert.throws(()=>validateBundle(...x),/artifact path/);});
test('rejects an artifact row count mismatch',()=>{const x=mk();x[0].artifacts[6].rows=4;assert.throws(()=>validateBundle(...x),/row count/);});
test('rejects inconsistent manifest validation counters',()=>{const x=mk();x[0].validation.kev_total=99;assert.throws(()=>validateBundle(...x),/validation counters/);});
