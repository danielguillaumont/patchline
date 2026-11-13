import { test, expect } from '@playwright/test';

const atlas = () => /Intelligence brief/i;
const methods = () => /Methods & quality/i;
const explorer = () => /Vulnerability explorer/i;

test('shows a clearly classified synthetic dataset and the actual summary', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');
  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('2 of 3 KEV records have a matching EPSS score.');
  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('fabricated test records');
  await expect(page.locator('.huge-stat')).toHaveText('66.67%');
  await expect(page.locator('.chart-header h3')).toContainText('4');
  const image = testInfo.outputPath('atlas.png');
  await page.screenshot({ path: image, fullPage: true });
  await testInfo.attach('Atlas', { path: image, contentType: 'image/png' });
});

test('selects nonzero and zero-count probability bands', async ({ page }) => {
  await page.goto('/');
  const bands = page.getByRole('group', { name: 'Inspect EPSS probability bands' }).getByRole('button');
  await expect(bands).toHaveCount(5);
  await bands.nth(4).click();
  await expect(page.locator('.band-inspector-metrics strong').first()).toHaveText('2');
  await expect(page.locator('.band-inspector-metrics strong').last()).toHaveText('50.00%');
  await expect(bands.nth(4)).toHaveAttribute('aria-pressed', 'true');
  await bands.nth(1).click();
  await expect(page.locator('.band-inspector-metrics strong').first()).toHaveText('0');
  await expect(page.locator('.band-inspector-metrics strong').last()).toHaveText('0.00%');
  await expect(page.locator('.band-inspector-description')).toContainText('Zero scored CVEs');
});

test('supports keyboard band selection', async ({ page }) => {
  await page.goto('/');
  const band = page.getByRole('group', { name: 'Inspect EPSS probability bands' }).getByRole('button').nth(2);
  await band.focus();
  await page.keyboard.press('Enter');
  await expect(band).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.band-inspector-metrics strong').last()).toHaveText('25.00%');
});

test('navigates to Methods and inspects manifest metadata without claiming browser verification', async ({ page }, testInfo) => {
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name: methods() }).click();
  await expect(page.getByRole('heading', { name: 'Evidence, file by file.' })).toBeVisible();
  const register = page.getByRole('group', { name: 'Select a manifest artifact' });
  await expect(register.getByRole('button')).toHaveCount(9);
  const parquet = register.getByRole('button').filter({ hasText: 'm04_epss_score_bands.parquet' });
  await parquet.click();
  await expect(parquet).toHaveAttribute('aria-pressed', 'true');
  const details = page.locator('#selected-artifact-details');
  await expect(details.getByRole('heading')).toHaveText('m04_epss_score_bands.parquet');
  await expect(details).toContainText('PARQUET');
  await expect(details).toContainText('5');
  await expect(details.locator('.artifact-digest')).toHaveText(/^[0-9a-f]{64}$/);
  await expect(details).toContainText(/NOT BROWSER-VERIFIED/i);
  const image = testInfo.outputPath('methods.png');
  await page.screenshot({ path: image, fullPage: true });
  await testInfo.attach('Evidence inspector', { path: image, contentType: 'image/png' });
});

test('retains an honest explorer preview without fabricated CVE records', async ({ page }) => {
  await page.goto('/');
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  await nav.getByRole('button', { name: explorer() }).click();
  await expect(page.getByRole('heading', { name: /A closer look/i })).toBeVisible();
  await expect(page.locator('main')).toContainText('not an approved CVE-level browser dataset');
  await nav.getByRole('button', { name: atlas() }).click();
  await expect(page.locator('.huge-stat')).toHaveText('66.67%');
});

test('contains the document at mobile and desktop widths', async ({ page }) => {
  await page.goto('/');
  for (const tab of [atlas(), methods(), explorer()]) {
    await page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name: tab }).click();
    const sizes = await page.evaluate(() => {
      const root = document.documentElement;
      const nav = document.querySelector('nav[aria-label="Primary navigation"]');
      return { viewport: root.clientWidth, page: root.scrollWidth,
        navScrollable: nav.scrollWidth > nav.clientWidth + 1 };
    });
    expect(sizes.page, `Document overflow for ${String(tab)}: ${JSON.stringify(sizes)}`).toBeLessThanOrEqual(sizes.viewport + 1);
    if (sizes.viewport <= 390) expect(sizes.navScrollable).toBe(true);
  }
});
