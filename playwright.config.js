// End-to-end tests: the real marketplace, real analyzer services, a throwaway
// database. Serial (one worker): specs share the server and its scan queue.
const { defineConfig, devices } = require('@playwright/test');

const PORT = Number(process.env.E2E_PORT || 3100);

module.exports = defineConfig({
  testDir: 'tests/e2e',
  workers: 1,
  fullyParallel: false,
  timeout: 180_000,
  expect: { timeout: 60_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'tests/e2e/report' }]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node tests/e2e/start-server.js',
    url: `http://127.0.0.1:${PORT}/api/mcs/stats`,
    timeout: 300_000,
    reuseExistingServer: false,
    // Own analyzer instances, so E2E never shares (or stops) the ones another run uses.
    env: { E2E_PORT: String(PORT), AST_TAINT_URL: 'http://127.0.0.1:8711', MODEL_B_URL: 'http://127.0.0.1:8775' },
  },
});
