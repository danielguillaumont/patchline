import {readFileSync} from 'node:fs';
import {test, expect} from '@playwright/test';
const testPack = readFileSync(new URL('../fixtures/research-review-invented.json', import.meta.url));

test('local-only review loads three invented findings, compares metrics, and switches readings', async ({page}) => {
  await page.goto('/research-review.html');
  await expect(page.getByRole('heading', {name: /From data to meaning/})).toBeVisible();
  await expect(page.getByText('No source data is bundled with this preview')).toBeVisible();
  await page.locator('#review-file').setInputFiles({name: 'invented-test-pack.json', mimeType: 'application/json', buffer: testPack});
  await expect(page.getByText('Invented example: highest band comparison')).toBeVisible();
  await expect(page.getByText('41.67%')).toBeVisible();
  await expect(page.getByText('8.00%')).toBeVisible();
  await page.getByRole('button', {name: /The completeness check/}).click();
  await expect(page.getByText('Invented example: full matching coverage')).toBeVisible();
  await expect(page.getByText('100.00%')).toBeVisible();
  await page.getByRole('button', {name: /The distribution shifts/}).click();
  await expect(page.getByText('75.00%')).toBeVisible();
  await expect(page.getByText('NO PUBLICATION APPROVAL')).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  expect(overflow).toBe(false);
});

test('rejects public-release flag without rendering unapproved data', async ({page}) => {
  await page.goto('/research-review.html');
  const edited=JSON.parse(testPack.toString('utf8'));
  edited.public_release_approved=true;
  await page.locator('#review-file').setInputFiles({name:'invalid.json', mimeType:'application/json',buffer:Buffer.from(JSON.stringify(edited))});
  await expect(page.getByRole('alert')).toContainText('publication status');
  await expect(page.getByText('Invented example: highest band comparison')).toHaveCount(0);
});
