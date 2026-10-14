const { test, expect } = require('@playwright/test');

test('watcher: a docs-only update keeps the fingerprint; bait-and-switch re-scans and FAILs', async ({ page }) => {
  await page.goto('/watcher');
  const update = type => page.waitForResponse(r => r.url().includes('/simulate-update') && r.request().postData().includes(type), { timeout: 150_000 });

  const docsDone = update('docs_only');
  await page.getByRole('button', { name: /Docs Only/ }).first().click();
  const docs = await (await docsDone).json();
  expect(docs.fingerprintChanged).toBe(false);
  expect(docs.rescanned).toBe(false);

  await page.goto('/watcher');
  const baitDone = update('bait_and_switch');
  await page.getByRole('button', { name: /Bait/ }).first().click();
  const bait = await (await baitDone).json();
  expect(bait.fingerprintChanged).toBe(true);
  expect(bait.newVerdict).toBe('FAIL');
  expect(bait.listingStatus).toBe('suspended');

  const detail = await (await page.request.get('/api/servers/weather-tools')).json();
  expect(detail.listing_status).toBe('suspended');
  const catalog = await (await page.request.get('/api/servers?limit=200')).json();
  expect(catalog.servers.map(s => s.slug)).not.toContain('weather-tools');

  // a clean re-scan restores the listing for later specs
  const rescan = await (await page.request.post('/api/mcs/scan', { data: { serverSlug: 'weather-tools' } })).json();
  expect(rescan.scanRecord.verdict).toBe('PASS');
  expect(rescan.listingStatus).toBe('approved');
});

test('verifier: an external candidate is scanned but never onboarded', async ({ page }) => {
  await page.goto('/verify');
  await page.getByRole('button', { name: 'Marketplace API' }).click();
  await page.fill('#mp-requester', 'E2E Market');
  await page.fill('#mp-url', 'demo:shell-runner');
  await page.click('#mp-btn');
  await expect(page.locator('#mp-result')).toContainText('FAIL', { timeout: 120_000 });
  const catalog = await (await page.request.get('/api/servers?limit=200')).json();
  expect(catalog.servers.some(s => /external/.test(s.slug))).toBe(false);
});
