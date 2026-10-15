const { test, expect } = require('@playwright/test');
const { watchErrors } = require('./helpers');
const { policyVersion } = require('../../src/mcpsecure/ruleset.json');

for (const [slug, pick, verdict, analyzerText] of [
  ['weather-tools', '#pick-weather', 'PASS', 'AST taint analyzer'],
  ['db-helper', '#pick-dbhelper', 'PASS', 'Model B'],
  ['docs-helper', '#pick-docshelper', 'REVIEW', 'AST taint analyzer'],
  ['shell-runner', '#pick-shell', 'FAIL', 'AST taint analyzer'],
]) {
  test(`scan page: ${slug} streams live stages and ends in ${verdict}`, async ({ page }) => {
    const errors = watchErrors(page);
    await page.goto('/scan');
    await page.click(pick);
    await page.click('#scan-btn');

    const live = page.locator('#mcs-live-list');
    await expect(live).toContainText('Ingest: pin source', { timeout: 120_000 });
    await expect(page.locator('#verdict-content')).toContainText(verdict, { timeout: 120_000 });
    await expect(page.locator('#parse-content')).toContainText('MCP tool(s) found');
    await expect(page.locator('#analyzers-grid')).toContainText(analyzerText);
    await expect(page.locator('#policy-content')).toContainText(policyVersion);
    expect(errors).toEqual([]);
  });
}

test('scan page: the code analyzers are real, and Model A is not part of this iteration', async ({ page }) => {
  await page.goto('/scan');
  await page.click('#pick-weather');
  await page.click('#scan-btn');
  await expect(page.locator('#verdict-content')).toContainText('PASS', { timeout: 120_000 });
  const ast = page.locator('.mcs-analyzer-card', { hasText: 'AST taint analyzer' });
  await expect(ast).toContainText('REAL ANALYSIS');
  await expect(page.locator('#analyzers-grid')).not.toContainText('Model A');
});
