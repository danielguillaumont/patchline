import test from 'node:test';
import assert from 'node:assert/strict';
import { validateBundle } from '../src/contract.mjs';
import { cohortReading } from '../src/cohort-inspector.mjs';
import { validateArtifactRegister } from '../src/evidence-inspector.mjs';

const models = [
  ['m03_epss_coverage_of_kev', 1],
  ['m04_epss_population_summary', 1],
  ['m04_epss_score_bands', 5],
  ['m05_kev_epss_cohort_bands', 6],
];
const labels = [
  '0.000 to <0.001', '0.001 to <0.010', '0.010 to <0.100',
  '0.100 to <0.500', '0.500 to 1.000 inclusive',
];
const bounds = [0, .001, .01, .1, .5, 1];
const sourceDate = '2026-01-15';
const retrieve = '2026-01-15T12:30:00Z';

const fixture = () => {
  const sources = [
    {source:'kev',snapshot_id:'kev-id',source_date:sourceDate,row_count:3,retrieved_at_utc:retrieve,model_version:null},
    {source:'epss',snapshot_id:'epss-id',source_date:sourceDate,row_count:4,retrieved_at_utc:retrieve,model_version:'v-ci-synthetic'},
  ];
  const artifacts = models.flatMap(([model, rows]) => ['csv','json','parquet'].map(ext => ({
    model, rows, path:`${model}.${ext}`, bytes:123, sha256:'f'.repeat(64), columns:['metric_id','band_order'],
  })));
  const manifest = {schema_id:'patchline.analytics-export.v2', data_kind:'synthetic_fixture',
    source_snapshots:sources, artifacts, validation:{kev_total:3,kev_matched:2,kev_unmatched:1,epss_scored_total:4}};
  const c = [{metric_id:'M03',denominator_total_kev:3,numerator_matched_kev:2,unmatched_kev:1,coverage_percent:200/3,
    kev_snapshot_id:'kev-id',epss_snapshot_id:'epss-id',kev_catalog_date_released:sourceDate,epss_source_date:sourceDate}];
  const s = [{metric_id:'M04',scored_cve_count:4,epss_snapshot_id:'epss-id',epss_source_date:sourceDate,
    min_epss:0,max_epss:1,mean_epss:.4525,p25_epss:.0075,median_epss:.405,p75_epss:.85,p90_epss:.94}];
  const fullCounts = [1,0,1,0,2];
  const kevCounts = [0,0,1,0,1];
  const bands = fullCounts.map((count,index) => ({metric_id:'M04',band_order:index+1,band_label:labels[index],
    lower_bound:bounds[index],upper_bound:bounds[index+1],upper_inclusive:index===4,
    cve_count:count,denominator_scored_cves:4,population_percent:count*25,
    epss_snapshot_id:'epss-id',epss_source_date:sourceDate}));
  const common = {metric_id:'M05',kev_snapshot_id:'kev-id',epss_snapshot_id:'epss-id',
    kev_catalog_date_released:sourceDate,epss_source_date:sourceDate,
    kev_retrieved_at_utc:retrieve,epss_retrieved_at_utc:retrieve,epss_model_version:'v-ci-synthetic',
    denominator_all_kev:3,denominator_scored_kev:2,unscored_kev:1};
  const cohort = bands.map((b,index) => ({...common,
    band_order:index+1,cohort_category:'scored_band',band_label:b.band_label,
    lower_bound:b.lower_bound,upper_bound:b.upper_bound,upper_inclusive:b.upper_inclusive,
    kev_cve_count:kevCounts[index],share_all_kev_percent:kevCounts[index]*100/3,
    share_scored_kev_percent:kevCounts[index]*50,
    full_epss_band_count:b.cve_count,full_epss_denominator:4,full_epss_population_percent:b.population_percent,
  }));
  cohort.push({...common,band_order:6,cohort_category:'unscored_kev',band_label:'No matching EPSS score',
    lower_bound:null,upper_bound:null,upper_inclusive:null,kev_cve_count:1,
    share_all_kev_percent:100/3,share_scored_kev_percent:null,full_epss_band_count:null,
    full_epss_denominator:null,full_epss_population_percent:null});
  return [manifest,c,s,bands,cohort];
};

const change = (action, message) => {
  const args = fixture(); action(args);
  assert.throws(() => validateBundle(...args), message);
};

test('accepts explicit v2 with twelve artifacts, six bands, and distinct denominator shares', () => {
  const result = validateBundle(...fixture());
  assert.equal(result.cohort.length,6);
  assert.equal(result.cohort[2].share_scored_kev_percent,50);
  assert.equal(result.cohort[2].full_epss_population_percent,25);
  assert.equal(result.cohort[5].share_scored_kev_percent,null);
  assert.equal(cohortReading(result.cohort[2]).scoredShare,'50.00%');
  assert.equal(cohortReading(result.cohort[5]).allKevShare,'33.33%');
});
test('rejects a v2 manifest without the required M05 JSON array', () => {
  const args = fixture(); assert.throws(() => validateBundle(...args.slice(0,4)), /six cohort/);
});
test('rejects an incomplete twelve-artifact v2 manifest', () => change(args => args[0].artifacts.pop(), /Incomplete source manifest/));
test('rejects a duplicate v2 artifact path', () => change(args => {args[0].artifacts[11].path=args[0].artifacts[10].path;}, /artifact path/));
test('rejects M05 counts inconsistent with M03', () => change(args => {args[4][2].kev_cve_count=2;}, /M05/));
test('rejects incorrect scored KEV denominators', () => change(args => {args[4][2].denominator_scored_kev=3;}, /denominator/));
test('rejects M05 probability shares computed from the wrong population', () => change(args => {args[4][2].share_scored_kev_percent=25;}, /scored bands/));
test('rejects M05 full-population band counts inconsistent with M04', () => change(args => {args[4][4].full_epss_band_count=3;}, /M04/));
test('rejects source snapshot substitutions', () => change(args => {args[4][0].kev_snapshot_id='other';}, /lineage/));
test('rejects a claimed zero EPSS score for unscored KEV', () => change(args => {args[4][5].share_scored_kev_percent=0;}, /unscored/));
test('rejects an imputed sixth probability interval', () => change(args => {args[4][5].lower_bound=0;}, /unscored/));
test('rejects a missing required v2 lineage field', () => change(args => {delete args[4][2].epss_retrieved_at_utc;}, /required fields/));
test('accepts twelve artifact records with M05 columns and correct row count', () => {
  const [manifest] = fixture();
  assert.equal(validateArtifactRegister(manifest.artifacts,Object.fromEntries(models)).length,12);
});

test('v2 accepts a fully empty snapshot pair with all shares undefined', () => {
  const args = fixture();
  args[0].source_snapshots.forEach(source => {source.row_count=0;});
  Object.assign(args[0].validation,{kev_total:0,kev_matched:0,kev_unmatched:0,epss_scored_total:0});
  Object.assign(args[1][0],{denominator_total_kev:0,numerator_matched_kev:0,unmatched_kev:0,coverage_percent:null});
  args[2][0].scored_cve_count=0;
  args[3].forEach(band => {band.cve_count=0;band.denominator_scored_cves=0;band.population_percent=null;});
  args[4].forEach(row => {row.kev_cve_count=0;row.denominator_all_kev=0;
    row.denominator_scored_kev=0;row.unscored_kev=0;
    row.share_all_kev_percent=null;row.share_scored_kev_percent=null;
    row.full_epss_band_count=row.band_order===6?null:0;
    row.full_epss_denominator=row.band_order===6?null:0;
    row.full_epss_population_percent=null;
  });
  const result=validateBundle(...args);
  assert.equal(result.cohort[0].share_scored_kev_percent,null);
  assert.equal(cohortReading(result.cohort[0]).scoredShare,'Not defined');
  assert.equal(result.cohort[5].kev_cve_count,0);
});
test('rejects fake zero percentages for empty v2 denominators', () => {
  const args=fixture();
  args[4][0].share_scored_kev_percent=null;
  assert.throws(()=>validateBundle(...args),/scored bands/);
});
