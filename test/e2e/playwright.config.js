// Playwright end-to-end suite for Scam Bunker. Dev-only: the app itself has no dependencies.
// Every spec runs twice: against the Node server (server mode) and against the GitHub Pages build
// served under /scam_bunker/ (static mode, no /api).
const { defineConfig, devices } = require('@playwright/test');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const SERVER_PORT = +(process.env.E2E_SERVER_PORT || 4410);
const STATIC_PORT = +(process.env.E2E_STATIC_PORT || 4411);
const CI = !!process.env.CI;

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: '*.spec.js',
  fullyParallel: true,
  forbidOnly: CI,
  retries: CI ? 1 : 0,
  workers: CI ? 2 : undefined,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: CI ? [['list'], ['html', { open: 'never' }], ['github']] : [['list'], ['html', { open: 'never' }]],
  use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 }, trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [
    { name: 'server', use: { baseURL: `http://127.0.0.1:${SERVER_PORT}/` } },
    { name: 'static', use: { baseURL: `http://127.0.0.1:${STATIC_PORT}/scam_bunker/` } },
  ],
  webServer: [
    {
      // Same as `npm start`, without loading a local .env, so no API keys change what the tests see.
      command: 'node server.js',
      cwd: ROOT,
      env: { ...process.env, PORT: String(SERVER_PORT), HOST: '127.0.0.1', OLLAMA_URL: 'http://127.0.0.1:9' },
      url: `http://127.0.0.1:${SERVER_PORT}/api/status`,
      reuseExistingServer: !CI,
      timeout: 30_000,
    },
    {
      command: `node scripts/build-pages.js && node test/e2e/serve-static.js ${STATIC_PORT}`,
      cwd: ROOT,
      url: `http://127.0.0.1:${STATIC_PORT}/scam_bunker/`,
      reuseExistingServer: !CI,
      timeout: 30_000,
    },
  ],
});
