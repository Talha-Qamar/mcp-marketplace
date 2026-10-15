const { test, expect } = require('@playwright/test');
const { login, watchErrors, waitForSubmission } = require('./helpers');

async function publishPreset(page, preset, name) {
  await page.goto('/publish');
  await page.evaluate(p => window.fillPreset(p), preset);
  await page.fill('#server-name', name);
  await page.click('#publish-btn');
  await expect(page.locator('#post-verdict-panel')).not.toBeEmpty({ timeout: 150_000 });
  return page.locator('#post-verdict-panel');
}

test('publishing requires a login', async ({ page }) => {
  await page.request.post('/api/auth/logout');
  await page.goto('/publish');
  await page.evaluate(() => window.fillPreset('pass'));
  page.once('dialog', d => d.accept());
  await page.click('#publish-btn');
  await expect(page).toHaveURL(/\/login/);
});

test('PASS preset: the server is approved and appears in the catalog', async ({ page }) => {
  const errors = watchErrors(page);
  await login(page, 'alice');
  const name = `E2E Weather ${Date.now()}`;
  const panel = await publishPreset(page, 'pass', name);
  await expect(panel).toContainText('Approved');
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const catalog = await (await page.request.get('/api/servers?limit=200&sort=newest')).json();
  expect(catalog.servers.map(s => s.slug)).toContain(slug);
  expect(errors).toEqual([]);
});

test('FAIL preset: rejected and never listed', async ({ page }) => {
  await login(page, 'alice');
  const name = `E2E Shell ${Date.now()}`;
  const panel = await publishPreset(page, 'fail', name);
  await expect(panel).toContainText('Rejected');
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const catalog = await (await page.request.get('/api/servers?limit=200&sort=newest')).json();
  expect(catalog.servers.map(s => s.slug)).not.toContain(slug);
  const detail = await (await page.request.get(`/api/servers/${slug}`)).json();
  expect(detail.listing_status).toBe('rejected');
});

test('REVIEW preset → admin queue → note required → approve → listed', async ({ page }) => {
  await login(page, 'alice');
  const name = `E2E Review ${Date.now()}`;
  const panel = await publishPreset(page, 'review', name);
  await expect(panel).toContainText('In review');
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

  // the publisher cannot see the queue
  await page.goto('/admin');
  await page.getByRole('button', { name: 'Review Queue' }).click();
  await expect(page.locator('#review-queue-list')).toContainText('admins only');

  await login(page, 'admin');
  await page.goto('/admin');
  await page.getByRole('button', { name: 'Review Queue' }).click();
  const card = page.locator('.review-card', { hasText: slug });
  await expect(card).toBeVisible();
  // the reviewer sees why: the rule and its evidence
  await expect(card).toContainText('Why this verdict');
  await expect(card).toContainText('built at runtime');

  // approving without a note is refused
  let dialog = '';
  page.once('dialog', d => { dialog = d.message(); d.accept(); });
  await card.getByRole('button', { name: /Approve/ }).click();
  expect(dialog).toContain('note');

  await card.locator('.review-note').fill('E2E: description file reviewed by hand; harmless.');
  await card.getByRole('button', { name: /Approve/ }).click();
  await expect(card).toContainText('(saved)');

  const detail = await (await page.request.get(`/api/servers/${slug}`)).json();
  expect(detail.listing_status).toBe('approved');
  expect(detail.security_status).toBe('reviewed');
});

test('a publisher cannot read or decide on someone else\'s submission', async ({ page }) => {
  await login(page, 'alice');
  const res = await page.request.post('/api/v1/submissions', { data: { name: `E2E Private ${Date.now()}`, source: { kind: 'demo', name: 'db-helper' } } });
  const { submission } = await res.json();
  await waitForSubmission(page, submission.id);
  await login(page, 'bob');
  expect((await page.request.get(`/api/v1/submissions/${submission.id}`)).status()).toBe(404);
  expect((await page.request.post(`/api/v1/submissions/${submission.id}/decision`, { data: { decision: 'approve', note: 'x' } })).status()).toBe(403);
});

test('the login form works at the clean URL /login (not only /login.html)', async ({ page }) => {
  for (const url of ['/login', '/login.html']) {
    await page.context().clearCookies();
    await page.goto(url);
    await page.fill('#email', 'alice_dev@example.com');
    await page.fill('#password', 'password123');
    await page.click('#login-form button[type=submit]');
    await expect.poll(async () => (await page.request.get('/api/auth/me')).status(), { timeout: 10_000 }).toBe(200);
  }
});
