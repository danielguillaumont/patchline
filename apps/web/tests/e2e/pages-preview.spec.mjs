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
    await region.getByLabel('EPSS STATUS').selectOption('all');
    await region.getByLabel('SEARCH FICTIONAL RECORDS').fill('CVE-2099-0003');
    await expect(region.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(1);
    await expect(region.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('CVE-2099-0003');
    await expect(region.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('absent EPSS');
    await region.getByRole('button',{name:'Clear filters'}).click();
    await expect(region.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(3);
    const sizes = await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
    expect(sizes.scroll).toBeLessThanOrEqual(sizes.width+1);
  }
});

// EA-05C1: presentation-only polish must retain public data boundaries and behavior.
test('public Explorer puts investigation controls high on a desktop viewport', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(siteBase);
  await page.getByRole('navigation', {name: 'Primary navigation'})
    .getByRole('button', {name: /Vulnerability explorer/i}).click();
  const region = page.getByRole('region', {name: 'Public fictional vulnerability explorer'});
  await expect(region).toBeVisible();
  const hero = await region.locator('.local-explorer-hero').boundingBox();
  const search = await region.getByLabel('SEARCH FICTIONAL RECORDS').boundingBox();
  expect(hero).not.toBeNull();
  expect(search).not.toBeNull();
  expect(hero.height).toBeLessThan(390);
  expect(search.y).toBeLessThan(900);
  const results = region.getByRole('group', {name: 'Select a fictional CVE'});
  const target = results.getByRole('button', {name: /CVE-2099-0003/});
  await target.click();
  await expect(target).toHaveAttribute('aria-pressed', 'true');
  await expect(region.getByRole('region', {name: 'Selected fictional CVE details'}))
    .toContainText('CVE-2099-0003');
});

test('public Explorer mobile filters and pending metrics remain readable without overflow', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(siteBase);
  await page.getByRole('navigation', {name: 'Primary navigation'})
    .getByRole('button', {name: /Vulnerability explorer/i}).click();
  const region = page.getByRole('region', {name: 'Public fictional vulnerability explorer'});
  await expect(region).toBeVisible();
  await region.getByLabel('EPSS STATUS').selectOption('missing');
  const results = region.getByRole('group', {name: 'Select a fictional CVE'});
  await expect(results.getByRole('button')).toHaveCount(2);
  const pending = results.getByRole('button', {name: /CVE-2099-9999/});
  await pending.click();
  await expect(pending).toHaveAttribute('aria-pressed', 'true');
  const detail = region.getByRole('region', {name: 'Selected fictional CVE details'});
  await expect(detail).toContainText('Awaiting Analysis');
  await expect(detail).toContainText('No CVSS metrics are present');
  const width = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
  }));
  expect(width.document).toBeLessThanOrEqual(width.viewport + 1);
});
