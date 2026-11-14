import { test, expect } from '@playwright/test';
import { constants, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pagesBase } from '../../scripts/pages-base.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const destination = join(repo, 'docs', 'assets');
const names = ['exploit-atlas-explorer-desktop.png', 'exploit-atlas-explorer-mobile.png'];

function assertPng(path, minimumWidth) {
  const data = readFileSync(path);
  const magic = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (data.length < 10_000 || !data.subarray(0, 8).equals(magic)
      || data.readUInt32BE(16) < minimumWidth || data.readUInt32BE(20) < 500) {
    throw Error(`Invalid fictional Explorer screenshot: ${path}`);
  }
}

test('capture two non-overwriting, approved fictional Explorer portfolio screenshots', async ({page}) => {
  for (const name of names) {
    if (existsSync(join(destination, name))) {
      throw Error(`Refusing to overwrite curated screenshot: docs/assets/${name}`);
    }
  }
  const scratch = mkdtempSync(join(tmpdir(), 'exploit-atlas-explorer-shots-'));
  const published = [];
  try {
    await page.goto(pagesBase());
    await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');
    await page.getByRole('navigation', {name: 'Primary navigation'})
      .getByRole('button', {name: /Vulnerability explorer/i}).click();
    const region = page.getByRole('region', {name: 'Public fictional vulnerability explorer'});
    await expect(region).toBeVisible();
    await expect(region.getByText('PUBLIC DEMO / FICTIONAL EXAMPLES ONLY')).toBeVisible();
    const results = region.getByRole('group', {name: 'Select a fictional CVE'});
    await expect(results.getByRole('button')).toHaveCount(3);
    await expect(region.getByRole('region', {name: 'Selected fictional CVE details'}))
      .toContainText('CVE-2099-0001');
    await page.evaluate(() => document.fonts.ready.then(() => true));
    await page.screenshot({path: join(scratch, names[0]), animations: 'disabled'});

    await page.setViewportSize({width: 390, height: 844});
    const pending = results.getByRole('button', {name: /CVE-2099-9999/});
    await pending.click();
    await expect(region.getByRole('region', {name: 'Selected fictional CVE details'}))
      .toContainText('Awaiting Analysis');
    const widths = await page.evaluate(() => ({
      page: document.documentElement.scrollWidth,
      viewport: document.documentElement.clientWidth,
    }));
    expect(widths.page).toBeLessThanOrEqual(widths.viewport + 1);
    await region.screenshot({path: join(scratch, names[1]), animations: 'disabled'});

    assertPng(join(scratch, names[0]), 1400);
    assertPng(join(scratch, names[1]), 390);
    mkdirSync(destination, {recursive: true});
    try {
      for (const name of names) {
        const target = join(destination, name);
        copyFileSync(join(scratch, name), target, constants.COPYFILE_EXCL);
        published.push(target);
      }
    } catch (error) {
      for (const file of published) unlinkSync(file);
      throw error;
    }
    for (const name of names) console.log(`Reviewed fictional screenshot: docs/assets/${name}`);
  } finally {
    rmSync(scratch, {recursive: true, force: true});
  }
});
