const { expect } = require('@playwright/test');

const USERS = {
  alice: { email: 'alice_dev@example.com', password: 'password123' },
  bob: { email: 'bob_builder@example.com', password: 'password123' },
  admin: { email: 'dave_sec@example.com', password: 'password123' },
};

/** Log in through the API; the session cookie lands in the page's browser context. */
async function login(page, who) {
  await page.request.post('/api/auth/logout').catch(() => {});
  const res = await page.request.post('/api/auth/login', { data: USERS[who] });
  expect(res.ok(), `login as ${who}`).toBeTruthy();
}

/** Collect page errors; console errors from the navbar's logged-out /auth/me probe are expected. */
function watchErrors(page) {
  const errors = [];
  page.on('pageerror', e => errors.push(`pageerror: ${e.message}`));
  page.on('console', m => {
    if (m.type() !== 'error') return;
    const t = m.text();
    if (/401|\/auth\/me/.test(t)) return;
    errors.push(`console: ${t}`);
  });
  return errors;
}

/** Wait until a submission leaves the queue, via the API. */
async function waitForSubmission(page, id) {
  await expect.poll(async () => (await (await page.request.get(`/api/v1/submissions/${id}`)).json()).submission.state,
    { timeout: 150_000, intervals: [1000] }).toMatch(/approved|in_review|rejected|failed/);
  return (await (await page.request.get(`/api/v1/submissions/${id}`)).json());
}

module.exports = { USERS, login, watchErrors, waitForSubmission };
