import { test, expect } from '@playwright/test';
import { QA_SESSIONS } from '../fixtures/maths-env.mjs';
import { setSessionCookie } from './helpers/session.mjs';

test('logged-in user can access /countdown', async ({ page, context }) => {
  await setSessionCookie(context, QA_SESSIONS.approved.token);

  await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
  await expect(page).not.toHaveURL(/\/login\/\?next=/);
  await expect(page.getByTestId('countdown-main')).toBeVisible();
  await expect(page.getByTestId('countdown-clock')).toBeVisible();
});
