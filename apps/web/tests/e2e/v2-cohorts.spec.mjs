import { test, expect } from '@playwright/test';

const atlas = () => /Intelligence brief/i;
const methods = () => /Methods & quality/i;

test('loads a validated v2 synthetic export and renders five scored cohorts plus unscored KEV', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');
  await expect(page.locator('.classification')).toContainText('patchline.analytics-export.v2');
  await expect(page.getByRole('heading', { name: 'The cohort in context.' })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Compare KEV and full EPSS probability bands' }).getByRole('button')).toHaveCount(5);
  await expect(page.locator('.cohort-unscored')).toContainText('No EPSS match is not zero probability.');
  await expect(page.locator('.cohort-unscored')).toContainText('33.33%');
  const file = testInfo.outputPath('v2-cohort-atlas.png');
  await page.screenshot({path:file,fullPage:true});
  await testInfo.attach('v2 cohort atlas', {path:file,contentType:'image/png'});
});

test('compares different denominators and retains zero-count cohorts', async ({ page }) => {
  await page.goto('/');
  const group = page.getByRole('group', { name: 'Compare KEV and full EPSS probability bands' });
  const buttons = group.getByRole('button');
  await buttons.nth(2).click();
  await expect(buttons.nth(2)).toHaveAttribute('aria-pressed','true');
  const selected = page.getByRole('region', { name: 'Selected cohort interval details' });
  await expect(selected).toContainText('25.00% of scored EPSS CVEs');
  await expect(selected).toContainText('50.00% of scored KEV CVEs');
  await buttons.nth(1).click();
  await expect(selected).toContainText('0.00% of scored EPSS CVEs');
  await expect(selected).toContainText('0.00% of scored KEV CVEs');
  await buttons.nth(4).focus();
  await page.keyboard.press('Enter');
  await expect(buttons.nth(4)).toHaveAttribute('aria-pressed','true');
});

test('lists twelve artifacts and displays M05 metadata honestly', async ({ page }, testInfo) => {
  await page.goto('/');
  await page.getByRole('navigation', {name:'Primary navigation'}).getByRole('button', {name:methods()}).click();
  await expect(page.locator('.quality-grid')).toContainText('12');
  const register = page.getByRole('group', {name:'Select a manifest artifact'});
  await expect(register.getByRole('button')).toHaveCount(12);
  const row = register.getByRole('button').filter({hasText:'m05_kev_epss_cohort_bands.parquet'});
  await row.click();
  const detail = page.getByRole('region', {name:'Selected artifact metadata'});
  await expect(detail).toContainText('M05 / KEV cohort');
  await expect(detail).toContainText('6');
  await expect(detail).toContainText(/NOT BROWSER-VERIFIED/i);
  await expect(detail.locator('.artifact-digest')).toHaveText(/^[a-f0-9]{64}$/);
  const file = testInfo.outputPath('v2-methods.png');
  await page.screenshot({path:file,fullPage:true});
  await testInfo.attach('v2 M05 evidence', {path:file,contentType:'image/png'});
});

test('provides a classified interpretation for the selected M05 interval', async ({ page }) => {
  await page.goto('/');
  const panel = page.getByRole('region', { name: 'Selected cohort interval interpretation' });
  await expect(panel).toContainText('1 of 2 scored KEV CVEs (50.00%)');
  await expect(panel).toContainText('1 of 4 full EPSS CVEs (25.00%)');
  await expect(panel).toContainText('overlapping distributions');
  await expect(panel).toContainText('Synthetic illustration');
  const buttons = page.getByRole('group', {name:'Compare KEV and full EPSS probability bands'}).getByRole('button');
  await buttons.nth(1).click();
  await expect(panel).toContainText('0 of 2 scored KEV CVEs');
});

test('keeps the document contained and existing atlas view functional', async ({ page }) => {
  await page.goto('/');
  const nav = page.getByRole('navigation', {name:'Primary navigation'});
  for (const name of [atlas(),methods()]) {
    await nav.getByRole('button', {name}).click();
    const sizes = await page.evaluate(() => ({
      viewport:document.documentElement.clientWidth,
      document:document.documentElement.scrollWidth,
    }));
    expect(sizes.document,JSON.stringify(sizes)).toBeLessThanOrEqual(sizes.viewport+1);
  }
  await nav.getByRole('button',{name:atlas()}).click();
  await expect(page.locator('.huge-stat')).toHaveText('66.67%');
  const epssBands = page.getByRole('group',{name:'Inspect EPSS probability bands'}).getByRole('button');
  await epssBands.nth(1).click();
  await expect(page.locator('.band-inspector-metrics strong').last()).toHaveText('0.00%');
});
