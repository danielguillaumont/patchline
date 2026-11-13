import { test, expect } from '@playwright/test';

test('explains the synthetic EPSS figure without creating an attack forecast', async ({ page }) => {
  await page.goto('/');
  const reading = page.getByRole('region', {name:'EPSS distribution interpretation'});
  await expect(reading).toContainText('2 of 4 scored CVEs');
  await expect(reading).toContainText('fabricated test counts');
  await expect(reading).toContainText('not how many attacks occurred');
});

test('expands glossary definitions from keyboard and stays inside mobile viewport', async ({ page }) => {
  await page.goto('/');
  const glossary = page.getByRole('region', {name:'Glossary of intelligence terms'});
  await expect(glossary.locator('details')).toHaveCount(8);
  const epss = glossary.locator('details').filter({has:page.locator('summary', {hasText:'EPSS'})});
  await epss.locator('summary').focus();
  await page.keyboard.press('Enter');
  await expect(epss).toHaveAttribute('open','');
  await expect(epss).toContainText('next 30 days');
  const layout = await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
  expect(layout.scroll,JSON.stringify(layout)).toBeLessThanOrEqual(layout.width+1);
});
