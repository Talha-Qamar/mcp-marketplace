const { test, expect } = require('@playwright/test');
const { login, waitForSubmission } = require('./helpers');

// Listing text is attacker-controlled. Every page that renders it must escape it.
const PAYLOAD = '<img src=x onerror="window.__xss=(window.__xss||0)+1">';

test('attacker-controlled listing text is never executed', async ({ page }) => {
  await login(page, 'alice');
  const res = await page.request.post('/api/v1/submissions', {
    data: {
      name: `XSS ${Date.now()} ${PAYLOAD}`,
      slug: `xss-${Date.now()}`,
      description: `desc ${PAYLOAD}`,
      long_description: `## Docs\n\n${PAYLOAD}\n\n<script>window.__xss=99</script>`,
      source: { kind: 'demo', name: 'db-helper' },
      declared_tools: [{ name: `t${PAYLOAD}`, description: PAYLOAD }],
    },
  });
  expect(res.status()).toBe(202);
  const { submission, server } = await res.json();
  await waitForSubmission(page, submission.id);

  await login(page, 'admin');
  for (const url of [`/server-detail?slug=${server.slug}`, '/admin', '/attestations', '/servers']) {
    await page.goto(url);
    if (url === '/admin') await page.getByRole('button', { name: 'Review Queue' }).click();
    await page.waitForTimeout(1500);
    expect(await page.evaluate(() => window.__xss), `script ran on ${url}`).toBeUndefined();
  }
});
