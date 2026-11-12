import test from 'node:test';
import assert from 'node:assert/strict';
import {bandReading} from '../src/band-inspector.mjs';

const band = (overrides = {}) => ({
  band_order: 2,
  band_label: '0.001 to <0.010',
  cve_count: 0,
  population_percent: 0,
  ...overrides,
});

test('retains exact zero-count bands with explicit zero share', () => {
  const reading = bandReading(band(), 4);
  assert.equal(reading.countLabel, '0');
  assert.equal(reading.shareLabel, '0.00%');
  assert.match(reading.emptyNote, /Zero scored CVEs/);
  assert.match(reading.accessibleLabel, /0 of 4 scored CVEs/);
});

test('uses source-provided interval and exported population share', () => {
  const reading = bandReading(band({cve_count: 1, population_percent: 25}), 4);
  assert.equal(reading.rangeLabel, '0.001 to <0.010');
  assert.equal(reading.shareLabel, '25.00%');
  assert.match(reading.accessibleLabel, /25.00% of the EPSS population/);
  assert.match(reading.emptyNote, /not only KEV/);
});

test('handles an empty source population without dividing by zero', () => {
  const reading = bandReading(band({population_percent: null}), 0);
  assert.equal(reading.shareLabel, 'Not defined');
  assert.match(reading.emptyNote, /shares are not defined/);
});

test('does not invent an interval when source label is absent', () => {
  const reading = bandReading(band({band_label: undefined}), 4);
  assert.equal(reading.rangeLabel, 'Band 2 (interval not provided)');
});

test('formats actual large counts and preserves source percent', () => {
  const reading = bandReading(band({cve_count: 12000, population_percent: 12.3456}), 100000);
  assert.equal(reading.countLabel, '12,000');
  assert.equal(reading.populationLabel, '100,000');
  assert.equal(reading.shareLabel, '12.35%');
});
