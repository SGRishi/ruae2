import { defineConfig } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL || process.env.BASE_URL || 'http://127.0.0.1:8789';
const useExternalBase = Boolean(process.env.PLAYWRIGHT_BASE_URL || process.env.BASE_URL);

export default defineConfig({
  testDir: './qa/e2e',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL,
    trace: 'on-first-retry',
    video: 'on-first-retry',
  },
  webServer: useExternalBase
    ? undefined
    : {
        command: 'npm run build && node qa/server.mjs',
        url: 'http://127.0.0.1:8789/healthz',
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      },
});
