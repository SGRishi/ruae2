import { defineConfig } from '@playwright/test';

const baseURL = process.env.BASE_URL || 'http://127.0.0.1:3000';
const useExternalBase = Boolean(process.env.BASE_URL);

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: /.*\.spec\.(mjs|ts)$/,
  timeout: 60_000,
  retries: 1,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  use: {
    baseURL,
    trace: 'on-first-retry',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: useExternalBase
    ? undefined
    : {
        command: 'PORT=3000 npm run build && PORT=3000 node qa/server.mjs',
        url: 'http://127.0.0.1:3000/healthz',
        reuseExistingServer: !process.env.CI,
        timeout: 90_000,
      },
});
