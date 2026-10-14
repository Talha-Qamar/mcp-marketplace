// Live demo against the public GitHub testbed: publish a testbed branch through
// the UI, then a real rug pull (a new commit pushed to `watcher-demo`) is found
// by the watcher's Poll Now, re-scanned and the listing suspended.
// Pushes to the testbed repository, so it only runs with E2E_LIVE_TESTBED=1.
const { test, expect } = require('@playwright/test');
const { execFileSync } = require('child_process');
const path = require('path');
const { login, watchErrors } = require('./helpers');

const testbed = action => execFileSync(process.execPath, [path.join(__dirname, '..', '..', 'scripts', 'testbed.js'), action],
  { encoding: 'utf8', timeout: 120_000 });

test.describe('live testbed', () => {
  test.skip(process.env.E2E_LIVE_TESTBED !== '1', 'set E2E_LIVE_TESTBED=1 (pushes to the public testbed repo)');
  test.setTimeout(600_000);

  test('testbed picker: a vulnerable branch is scanned live from GitHub and rejected', async ({ page }) => {
    const errors = watchErrors(page);
    await login(page, 'alice');
    await page.goto('/publish');
    await expect(page.locator('#testbed-wrap')).toBeVisible();
    await page.selectOption('#testbed-select', 'case:cmd-injection-exec-ts');
    await expect(page.locator('#github-url')).toHaveValue(/mcp-secure-testbed\/tree\/cmd-injection-exec-ts$/);
    await page.fill('#server-name', `Live TS exec ${Date.now()}`);
    await page.click('#publish-btn');
    const panel = page.locator('#post-verdict-panel');
    await expect(panel).not.toBeEmpty({ timeout: 300_000 });
    await expect(panel).toContainText(/Rejected|In review/);
    expect(errors).toEqual([]);
  });

  test('rug pull: approved clean version, malicious commit pushed, Poll Now suspends the listing', async ({ page }) => {
    testbed('reset');
    await login(page, 'alice');
    await page.goto('/publish');
    await page.selectOption('#testbed-select', 'case:watcher-demo');
    const name = `Live watcher ${Date.now()}`;
    await page.fill('#server-name', name);
    await page.click('#publish-btn');
    await expect(page.locator('#post-verdict-panel')).toContainText('Approved', { timeout: 300_000 });
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    try {
      testbed('rugpull');
      await page.goto('/watcher');
      await page.getByRole('button', { name: /Poll Now/ }).click();
      await expect(page.locator('#watcher-update-result')).toContainText(new RegExp(`${name}.*new commit`), { timeout: 120_000 });
      await expect.poll(async () => (await (await page.request.get(`/api/servers/${slug}`)).json()).listing_status,
        { timeout: 300_000, intervals: [2000] }).toBe('suspended');
      // A second poll sees the same commit and does nothing.
      await page.getByRole('button', { name: /Poll Now/ }).click();
      await expect(page.locator('#watcher-update-result')).toContainText(new RegExp(`${name}: up to date`));
    } finally {
      testbed('reset');
    }
  });
});
