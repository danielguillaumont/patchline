import { test, expect } from '@playwright/test';
import { constants, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const destination = join(repo, 'docs', 'assets');
const imageNames = [
  'spectral-index-atlas.png',
  'spectral-index-cohort.png',
  'spectral-index-evidence.png',
  'spectral-index-mobile.png',
];

function assertPng(path) {
  const data = readFileSync(path);
  const pngMagic = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (data.length < 10_000 || !data.subarray(0, 8).equals(pngMagic)
      || data.readUInt32BE(16) < 300 || data.readUInt32BE(20) < 300) {
    throw Error(`Generated portfolio screenshot is invalid: ${path}`);
  }
}

test('capture four reviewable screenshots from a verified synthetic v2 fixture', async ({ page }) => {
  for (const name of imageNames) {
    if (existsSync(join(destination, name))) {
      throw Error(`Refusing to overwrite an existing curated screenshot: docs/assets/${name}`);
    }
  }

  const scratch = mkdtempSync(join(tmpdir(), 'patchline-portfolio-'));
  const published = [];
  try {
    await page.goto('/');
    await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');
    await expect(page.locator('.classification')).toContainText('patchline.analytics-export.v2');
    await expect(page.locator('.huge-stat')).toHaveText('66.67%');
    await page.screenshot({ path: join(scratch, imageNames[0]), animations: 'disabled' });

    const group = page.getByRole('group', { name: 'Compare KEV and full EPSS probability bands' });
    const thirdBand = group.getByRole('button').nth(2);
    await thirdBand.click();
    await expect(thirdBand).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('region', { name: 'Selected cohort interval details' }))
      .toContainText('50.00% of scored KEV CVEs');
    await page.locator('.cohort-section').screenshot({
      path: join(scratch, imageNames[1]), animations: 'disabled',
    });

    await page.getByRole('navigation', { name: 'Primary navigation' })
      .getByRole('button', { name: /Methods & quality/i }).click();
    const register = page.getByRole('group', { name: 'Select a manifest artifact' });
    const parquet = register.getByRole('button').filter({ hasText: 'm05_kev_epss_cohort_bands.parquet' });
    await parquet.click();
    await expect(page.getByRole('region', { name: 'Selected artifact metadata' }))
      .toContainText('NOT BROWSER-VERIFIED');
    await page.locator('.artifact-section').screenshot({
      path: join(scratch, imageNames[2]), animations: 'disabled',
    });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole('navigation', { name: 'Primary navigation' })
      .getByRole('button', { name: /Intelligence atlas/i }).click();
    await expect(page.getByRole('heading', { name: 'The cohort in context.' })).toBeVisible();
    const bounds = await page.evaluate(() => ({
      body: document.documentElement.scrollWidth,
      viewport: document.documentElement.clientWidth,
    }));
    expect(bounds.body).toBeLessThanOrEqual(bounds.viewport + 1);
    await page.evaluate(() => {
      const cohort = document.querySelector('.cohort-section');
      if (!cohort) throw Error('Missing cohort section');
      window.scrollTo(0, window.scrollY + cohort.getBoundingClientRect().top);
    });
    await page.screenshot({ path: join(scratch, imageNames[3]), animations: 'disabled' });

    for (const name of imageNames) assertPng(join(scratch, name));
    mkdirSync(destination, { recursive: true });
    try {
      for (const name of imageNames) {
        const target = join(destination, name);
        copyFileSync(join(scratch, name), target, constants.COPYFILE_EXCL);
        published.push(target);
      }
    } catch (error) {
      for (const target of published) unlinkSync(target);
      throw error;
    }
    for (const name of imageNames) console.log(`Curated synthetic screenshot: docs/assets/${name}`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
