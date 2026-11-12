import { test, expect } from '@playwright/test';

test('serves only the synthetic v2 showcase under the repository path', async ({page}) => {
  const urls = [];
  page.on('request', request => {
    if (request.url().includes('/demo/')) urls.push(new URL(request.url()).pathname);
  });
  await page.goto('/patchline/');
  await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');
  await expect(page.locator('.classification')).toContainText('patchline.analytics-export.v2');
  await expect(page.locator('.huge-stat')).toHaveText('66.67%');
  await expect(page.getByRole('heading', {name:'The cohort in context.'})).toBeVisible();
  expect(urls).toContain('/patchline/demo/manifest.json');
  expect(urls.length).toBe(5);
  expect(urls.every(url => url.startsWith('/patchline/demo/'))).toBe(true);
});

test('retains cohort and evidence interactions on the static preview', async ({page}) => {
  await page.goto('/patchline/');
  const group = page.getByRole('group', {name:'Compare KEV and full EPSS probability bands'});
  await group.getByRole('button').nth(2).click();
  await expect(page.getByRole('region',{name:'Selected cohort interval details'})).toContainText('50.00% of scored KEV CVEs');
  await page.getByRole('navigation',{name:'Primary navigation'}).getByRole('button',{name:/Methods & quality/i}).click();
  await expect(page.getByRole('group',{name:'Select a manifest artifact'}).getByRole('button')).toHaveCount(12);
  const sizes=await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
  expect(sizes.scroll).toBeLessThanOrEqual(sizes.width+1);
});
