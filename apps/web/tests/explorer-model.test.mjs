import test from 'node:test';
import assert from 'node:assert/strict';
import { localExplorerFixture } from '../src/explorer-local-fixture.mjs';
import { validateLocalExplorerFixture, filterExplorerRecords, epssText, cvssText } from '../src/explorer-model.mjs';
const clone = () => structuredClone(localExplorerFixture);
const rows = () => validateLocalExplorerFixture(clone()).records;

test('local fixture is explicitly fictional and not publicly approved', () => {
  const fixture = validateLocalExplorerFixture(clone());
  assert.equal(fixture.public_release_approved, false);
  assert.equal(fixture.records.length, 3);
  assert.ok(fixture.records.every(row=>row.cve_id.startsWith('CVE-2099-')));
});
test('filtering returns deterministic CVE ordering', () => {
  assert.deepEqual(filterExplorerRecords(rows().reverse()).map(row=>row.cve_id), ['CVE-2099-0001','CVE-2099-0003','CVE-2099-9999']);
});
test('case-insensitive matching searches CVE ID and title', () => {
  assert.equal(filterExplorerRecords(rows(), {query:'2099-0003'}).length, 1);
  assert.equal(filterExplorerRecords(rows(), {query:'NETWORK SERVICE'}).length, 1);
});
test('whitespace-only search does not exclude records', () => assert.equal(filterExplorerRecords(rows(),{query:'  '}).length,3));
test('KEV listed and not-listed filters preserve membership', () => {
  assert.deepEqual(filterExplorerRecords(rows(),{kev:'yes'}).map(x=>x.cve_id), ['CVE-2099-0001','CVE-2099-0003']);
  assert.deepEqual(filterExplorerRecords(rows(),{kev:'no'}).map(x=>x.cve_id), ['CVE-2099-9999']);
});
test('missing EPSS is distinct from genuine zero', () => {
  assert.equal(epssText(0),'0.00%');
  assert.equal(epssText(null),'Not scored');
  assert.deepEqual(filterExplorerRecords(rows(),{epss:'scored'}).map(x=>x.cve_id), ['CVE-2099-0001']);
  assert.equal(filterExplorerRecords(rows(),{epss:'missing'}).length,2);
});
test('analysis filtering keeps pending record separate', () => {
  assert.equal(filterExplorerRecords(rows(),{analysis:'analyzed'}).length,2);
  assert.deepEqual(filterExplorerRecords(rows(),{analysis:'pending'}).map(x=>x.cve_id),['CVE-2099-9999']);
});
test('combined filters and no-match query return empty', () => {
  assert.equal(filterExplorerRecords(rows(),{kev:'yes',epss:'scored',analysis:'pending'}).length,0);
  assert.equal(filterExplorerRecords(rows(),{query:'nonexistent'}).length,0);
});
test('CVSS version remains displayed and missing CVSS stays unavailable', () => {
  assert.equal(cvssText(rows()[0].cvss),'9.8 / CVSS 3.1');
  assert.equal(cvssText([]),'Not available');
});
test('unknown filter values are rejected', () => assert.throws(()=>filterExplorerRecords(rows(),{epss:'zero'}),/Invalid explorer filters/));
test('public approval mutation is rejected', () => {
  const fixture=clone(); fixture.public_release_approved=true;
  assert.throws(()=>validateLocalExplorerFixture(fixture),/publication boundary/);
});
test('source provenance mutation is rejected', () => {
  const fixture=clone(); fixture.provenance='archived_real_source';
  assert.throws(()=>validateLocalExplorerFixture(fixture),/provenance/);
});
test('realistic CVE year is not accepted as fictional test ID', () => {
  const fixture=clone(); fixture.records[0].cve_id='CVE-2026-0001';
  assert.throws(()=>validateLocalExplorerFixture(fixture),/fictional CVE ID/);
});
test('invented additional CVE row is not allowed', () => {
  const fixture=clone(); fixture.records.push({...fixture.records[0],cve_id:'CVE-2099-4444'});
  assert.throws(()=>validateLocalExplorerFixture(fixture),/three fictional examples/);
});
test('duplicate ID is not allowed', () => {
  const fixture=clone(); fixture.records[1].cve_id=fixture.records[0].cve_id;
  assert.throws(()=>validateLocalExplorerFixture(fixture),/fictional CVE ID/);
});
test('null EPSS cannot be paired with zero percentile', () => {
  const fixture=clone(); fixture.records[1].epss_percentile=0;
  assert.throws(()=>validateLocalExplorerFixture(fixture),/EPSS null-vs-zero/);
});
test('EPSS cannot be negative or NaN', () => {
  for(const value of [-0.1,Number.NaN,1.1]) {
    const fixture=clone(); fixture.records[0].epss=value;
    assert.throws(()=>validateLocalExplorerFixture(fixture),/EPSS null-vs-zero/);
  }
});
test('KEV presence requires date and absence requires null', () => {
  const fixture=clone(); fixture.records[2].kev=true;
  assert.throws(()=>validateLocalExplorerFixture(fixture),/KEV semantics/);
});
test('CVSS distinct metric versions cannot collapse into one score', () => {
  const fixture=clone(); fixture.records[0].cvss[1].version='3.1';
  assert.throws(()=>validateLocalExplorerFixture(fixture),/distinct versions/);
});
test('CVSS missing metric must not acquire synthetic zero severity', () => {
  const fixture=clone(); fixture.records[0].cvss[1].score=0;
  assert.throws(()=>validateLocalExplorerFixture(fixture),/CVSS missing vs present/);
});
test('unexpected record fields are not silently accepted', () => {
  const fixture=clone(); fixture.records[0].risk_score=100;
  assert.throws(()=>validateLocalExplorerFixture(fixture),/record shape/);
});
