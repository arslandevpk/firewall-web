const { defineConfig, devices } = require('@playwright/test');
const fs = require('fs');

const venvPython = 'firewall-web-standalone/.venv/bin/python';
const python = process.env.FIREWALL_WEB_PYTHON ||
  (fs.existsSync(venvPython) ? venvPython : 'python3');

module.exports = defineConfig({
  testDir: './tests/browser',
  timeout: 30000,
  expect: { timeout: 5000 },
  fullyParallel: false,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:5535',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'], browserName: 'chromium', viewport: { width: 1280, height: 900 } } },
    { name: 'mobile-chromium', use: { ...devices['iPhone 13'], browserName: 'chromium' } },
  ],
  webServer: {
    command: `NFT_SECRET=1234 NFT_HOST=127.0.0.1 NFT_PORT=5535 NFT_BACKEND=inspection ${python} firewall-web-standalone/firewall_web.py`,
    url: 'http://127.0.0.1:5535',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
