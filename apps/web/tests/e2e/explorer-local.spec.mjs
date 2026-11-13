import { test, expect } from '@playwright/test';

async function enter(page) {
  await page.goto('/');
  await page.getByRole('navigation',{name:'Primary navigation'}).getByRole('button',{name:/Vulnerability explorer/}).click();
  await expect(page.getByRole('region',{name:'Local synthetic vulnerability explorer'})).toBeVisible();
}

test('local Explorer displays three classified fictional records and an inspectable detail', async ({page}) => {
  await enter(page);
  await expect(page.getByText('DEV ONLY / NOT PUBLICATION APPROVED')).toBeVisible();
  const group=page.getByRole('group',{name:'Select a fictional CVE'});
  await expect(group.getByRole('button')).toHaveCount(3);
  await expect(page.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('9.8 / CVSS 3.1');
  await expect(page.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('0.00%');
  await group.getByRole('button',{name:/CVE-2099-0003/}).click();
  await expect(page.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('Not scored');
  await expect(page.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('not a score of zero');
});

test('search, KEV and EPSS filters and reset are functional', async ({page}) => {
  await enter(page);
  await page.getByLabel('KEV STATUS').selectOption('yes');
  await expect(page.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(2);
  await page.getByLabel('EPSS STATUS').selectOption('missing');
  await expect(page.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(1);
  await page.getByLabel('SEARCH FICTIONAL RECORDS').fill('NOTHING MATCHES');
  await expect(page.getByText('No matches in this tiny fixture.')).toBeVisible();
  await page.getByRole('button',{name:'Reset search and filters'}).click();
  await expect(page.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button')).toHaveCount(3);
});

test('CVE selection works by keyboard and avoids horizontal overflow', async ({page}) => {
  await enter(page);
  const buttons=page.getByRole('group',{name:'Select a fictional CVE'}).getByRole('button');
  await buttons.nth(2).focus(); await page.keyboard.press('Enter');
  await expect(buttons.nth(2)).toHaveAttribute('aria-pressed','true');
  await expect(page.getByRole('region',{name:'Selected fictional CVE details'})).toContainText('Awaiting Analysis');
  const widths=await page.evaluate(()=>({page:document.documentElement.scrollWidth,viewport:document.documentElement.clientWidth}));
  expect(widths.page).toBeLessThanOrEqual(widths.viewport+1);
});
