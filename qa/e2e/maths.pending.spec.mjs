import { test, expect } from '@playwright/test';
import { QA_SESSIONS } from '../fixtures/maths-env.mjs';
import { setSessionCookie } from './helpers/session.mjs';

test('authenticated but unapproved user is blocked', async ({ page, context }) => {
  await setSessionCookie(context, QA_SESSIONS.pending.token);

  await page.goto('/maths', { waitUntil: 'domcontentloaded' });
  await expect(page).toHaveURL(/\/maths\/?$/);
  await expect(page.getByTestId('maths-status')).toContainText(/pending approval/i);

  const protectedRes = await page.request.get('/api/protected/example');
  expect(protectedRes.status()).toBe(403);

  const yearsRes = await page.request.get('/api/maths/years');
  expect(yearsRes.status()).toBe(403);
});

