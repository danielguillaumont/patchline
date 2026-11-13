import test from 'node:test';
import assert from 'node:assert/strict';
import { glossaryTerms, distributionOverview, cohortIntervalNarrative } from '../src/interpretation.mjs';

const bands = [
  {band_order:1, band_label:'0.000 to <0.001', cve_count:1, population_percent:25},
  {band_order:2, band_label:'0.001 to <0.010', cve_count:0, population_percent:0},
  {band_order:3, band_label:'0.010 to <0.100', cve_count:1, population_percent:25},
  {band_order:4, band_label:'0.100 to <0.500', cve_count:0, population_percent:0},
  {band_order:5, band_label:'0.500 to 1.000 inclusive', cve_count:2, population_percent:50},
];
const row = {
  cohort_category:'scored_band', band_label:'0.010 to <0.100', kev_cve_count:1,
  share_scored_kev_percent:50, full_epss_band_count:1, full_epss_population_percent:25,
};

test('source-scoped summary names the largest M04 band and correct denominator', () => {
  const reading = distributionOverview('synthetic_fixture', bands, 4);
  assert.match(reading.headline, /2 of 4 scored CVEs/);
  assert.match(reading.detail, /0.500 to 1.000 inclusive \(50.00%/);
  assert.match(reading.scope, /fabricated test counts/);
  assert.doesNotMatch(reading.headline, /risk|attack probability/i);
});
test('describes archived source scope without a live claim', () => {
  const reading = distributionOverview('archived_source_snapshots', bands, 4);
  assert.match(reading.scope, /Archived source-pair/);
  assert.match(reading.scope, /Not a live measure/);
});
test('empty M04 population has undefined shares, not fictitious zero percentages', () => {
  const empty = bands.map(b => ({...b,cve_count:0,population_percent:null}));
  const reading = distributionOverview('synthetic_fixture',empty,0);
  assert.match(reading.headline, /no scored CVEs/);
  assert.match(reading.detail, /not defined/);
});
test('rejects absent classification and irreconcilable M04 populations', () => {
  assert.throws(()=>distributionOverview('unknown',bands,4), /reconciled/);
  assert.throws(()=>distributionOverview('synthetic_fixture',bands,5), /reconciled/);
  assert.throws(()=>distributionOverview('synthetic_fixture',bands.slice(0,4),4), /reconciled/);
});
test('keeps all cohort denominator labels precise', () => {
  const x = cohortIntervalNarrative('synthetic_fixture', row, 2, 4);
  assert.match(x.detail,/1 of 2 scored KEV CVEs \(50.00%\)/);
  assert.match(x.detail,/1 of 4 full EPSS CVEs \(25.00%\)/);
  assert.match(x.caveat,/overlapping distributions/);
  assert.match(x.scope,/Synthetic illustration/);
});
test('does not treat missing denominator as 0% probability', () => {
  const empty = {...row,kev_cve_count:0,share_scored_kev_percent:null,full_epss_band_count:0,full_epss_population_percent:null};
  const x=cohortIntervalNarrative('synthetic_fixture',empty,0,0);
  assert.match(x.detail,/not defined/);
  assert.doesNotMatch(x.detail,/0.00%/);
});
test('rejects inconsistent M05 shares and non-scored categories', () => {
  assert.throws(()=>cohortIntervalNarrative('synthetic_fixture',{...row,share_scored_kev_percent:99},2,4),/reconcile/);
  assert.throws(()=>cohortIntervalNarrative('synthetic_fixture',{...row,cohort_category:'unscored_kev'},2,4),/scored interval/);
  assert.throws(()=>cohortIntervalNarrative('synthetic_fixture',row,0,4),/scored interval/);
});
test('glossary covers every planned term without suggesting a risk score', () => {
  assert.deepEqual(glossaryTerms.map(x=>x.term), ['CVE','KEV','EPSS','CVSS','Coverage','Population','Cohort','Percentile']);
  assert.match(glossaryTerms.find(x=>x.term==='EPSS').meaning,/next 30 days/);
  assert.match(glossaryTerms.find(x=>x.term==='Cohort').meaning,/overlap/);
});
