import { test, expect } from '@playwright/test';
import { pagesBase } from '../../scripts/pages-base.mjs';

const siteBase = pagesBase();

test('serves only the synthetic v2 showcase under the repository path', async ({page}) => {
  const urls = [];
  page.on('request', request => {
    if (request.url().includes('/demo/')) urls.push(new URL(request.url()).pathname);
  });
  await page.goto(siteBase);
  await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');
  await expect(page.locator('.wordmark').first()).toContainText('Exploit Atlas');
  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('SYNTHETIC EXAMPLE');
  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('not real-world exploitation trends');
  await expect(page.locator('.classification')).toContainText('patchline.analytics-export.v2');
  await expect(page.locator('.huge-stat')).toHaveText('66.67%');
  await expect(page.getByRole('heading', {name:'The cohort in context.'})).toBeVisible();
  expect(urls).toContain(`${siteBase}demo/manifest.json`);
  expect(urls.length).toBe(5);
  expect(urls.every(url => url.startsWith(`${siteBase}demo/`))).toBe(true);
});

test('retains cohort and evidence interactions on the static preview', async ({page}) => {
  await page.goto(siteBase);
  const group = page.getByRole('group', {name:'Compare KEV and full EPSS probability bands'});
  await group.getByRole('button').nth(2).click();
  await expect(page.getByRole('region',{name:'Selected cohort interval details'})).toContainText('50.00% of scored KEV CVEs');
  await page.getByRole('navigation',{name:'Primary navigation'}).getByRole('button',{name:/Methods & quality/i}).click();
  await expect(page.getByRole('group',{name:'Select a manifest artifact'}).getByRole('button')).toHaveCount(12);
  const sizes=await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
  expect(sizes.scroll).toBeLessThanOrEqual(sizes.width+1);
});

// On pending approval the existing aggregate-only public Explorer placeholder must
// remain. A later separately reviewed approval turns on the fictional-only interface.
test('public Explorer respects the repository review gate', async ({page}) => {
  const { releaseFromRepo } = await import('../../scripts/explorer-public-release.mjs');
  const approved = releaseFromRepo().enabled;
  await page.goto(siteBase);
  await page.getByRole('navigation',{name:'Primary navigation'})
    .getByRole('button',{name:/Vulnerability explorer/}).click();
  if (!approved) {
    await expect(page.getByText('The current contracts publish validated aggregate metrics')).toBeVisible();
    await expect(page.getByRole('region',{name:'Public fictional vulnerability explorer'})).toHaveCount(0);
  } else {
    const region=page.getByRole('region',{name:'Public fictional vulnerability explorer'});
    await expect(region).toBeVisible();
    await expect(region.getByText('PUBLIC DEMO / FICTIONAL EXAMPLES ONLY')).toBeVisible();
    await expect(region.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(3);
    await region.getByLabel('EPSS STATUS').selectOption('missing');
    await expect(region.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(2);
  }
});
