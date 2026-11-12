import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoFileUrl } from '../src/demo-url.mjs';

const file = 'm05_kev_epss_cohort_bands.json';

test('keeps normal local Vite loading at the root base', () => {
  assert.equal(demoFileUrl('/', file), '/demo/m05_kev_epss_cohort_bands.json');
});

test('loads synthetic demo beneath the GitHub Pages repository path', () => {
  assert.equal(demoFileUrl('/patchline/', 'manifest.json'), '/patchline/demo/manifest.json');
});

test('supports another safe project base for preview testing', () => {
  assert.equal(demoFileUrl('/preview/patchline/', file), '/preview/patchline/demo/m05_kev_epss_cohort_bands.json');
});

test('rejects unsafe and absolute base URLs', () => {
  for (const base of ['', 'patchline/', '//example.com/', '/patchline', '/a/../', '/a?x=1/', 'https://example.com/']) {
    assert.throws(() => demoFileUrl(base, file));
  }
});

test('rejects unsupported filenames and path traversal', () => {
  for (const name of ['../../secrets.json', 'm03_epss_coverage_of_kev.csv', 'unknown.json', '/manifest.json']) {
    assert.throws(() => demoFileUrl('/patchline/', name));
  }
});
