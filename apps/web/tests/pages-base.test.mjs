import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pagesBase } from '../scripts/pages-base.mjs';

test('preserves the old project site before repository rename', () => {
  assert.equal(pagesBase({ GITHUB_REPOSITORY: 'danielguillaumont/patchline' }), '/patchline/');
});

test('automatically chooses the new site after repository rename', () => {
  assert.equal(pagesBase({ GITHUB_REPOSITORY: 'danielguillaumont/exploit-atlas' }), '/exploit-atlas/');
});

test('supports a deliberate future-path rehearsal', () => {
  assert.equal(pagesBase({ GITHUB_REPOSITORY: 'danielguillaumont/patchline', EXPLOIT_ATLAS_PAGES_SITE: 'exploit-atlas' }), '/exploit-atlas/');
});

test('retains the current site for local preview without GitHub context', () => {
  assert.equal(pagesBase({}), '/patchline/');
});

test('rejects unknown repository identities and unsafe overrides', () => {
  for (const repo of ['owner/unknown', 'unknown', 'owner/../bad', 'owner/repo/subfolder']) {
    assert.throws(() => pagesBase({ GITHUB_REPOSITORY: repo }), /Unexpected/);
  }
  for (const override of ['/', '/exploit-atlas/', '../exploit-atlas', 'anything']) {
    assert.throws(() => pagesBase({ EXPLOIT_ATLAS_PAGES_SITE: override }), /Unsupported/);
  }
});
