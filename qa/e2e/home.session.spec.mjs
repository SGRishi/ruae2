import { test, expect } from '@playwright/test';
import { QA_SESSIONS } from '../fixtures/maths-env.mjs';
import { setSessionCookie } from './helpers/session.mjs';
import { installCountdownTestClock, stubBackgroundImages } from '../../tests/e2e/helpers/countdown.mjs';

test.describe('homepage session experience', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('anonymous user sees login CTA and guest actions', async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('home-login-link')).toContainText(/create account \/ login/i);
    await expect(page.getByTestId('home-guest-actions')).toBeVisible();
    await expect(page.getByTestId('home-session-panel')).toBeHidden();
  });

  test('approved logged-in user sees welcome state with RUAE/Maths/Countdown shortcuts', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('home-session-panel')).toBeVisible();
    await expect(page.getByTestId('home-session-greeting')).toContainText(
      new RegExp(`welcome back,\\s*${QA_SESSIONS.approved.username}`, 'i')
    );
    await expect(page.getByTestId('home-session-ruae')).toBeVisible();
    await expect(page.getByTestId('home-session-maths')).toBeVisible();
    await expect(page.getByTestId('home-session-countdown')).toBeVisible();
    await expect(page.getByTestId('home-guest-actions')).toBeHidden();
    await expect(page.getByTestId('home-login-link')).toContainText(/welcome back/i);
  });

  test('logged-in user can open countdown from homepage shortcut without login redirect', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await page.getByTestId('home-session-countdown').click();

    await expect(page).toHaveURL(/\/countdown\/?$/);
    await expect(page).not.toHaveURL(/\/login\/\?next=/);
    await expect(page.getByTestId('countdown-main')).toBeVisible();
  });
});
