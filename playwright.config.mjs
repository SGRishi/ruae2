import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './qa/e2e',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://127.0.0.1:8789',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run build && node qa/server.mjs',
    url: 'http://127.0.0.1:8789/healthz',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
