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
    await expect(page.getByTestId('home-returning-bg')).toBeHidden();
    await expect(page.locator('.hero')).toBeVisible();
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
    await expect(page.getByTestId('home-returning-bg')).toBeVisible();
    await expect(page.locator('.hero')).toBeHidden();
    await expect(page.getByRole('heading', { name: /stop juggling tabs/i })).toBeHidden();

    await expect(page.locator('[data-testid=\"home-session-panel\"] .returning-actions a')).toHaveCount(3);
    await expect(page.getByTestId('home-session-ruae')).toHaveText(/english/i);
    await expect(page.getByTestId('home-session-maths')).toHaveText(/maths/i);
    await expect(page.getByTestId('home-session-countdown')).toHaveText(/countdown/i);

    const backgroundImage = await page.getByTestId('home-returning-bg').evaluate((node) => {
      return globalThis.getComputedStyle(node).backgroundImage;
    });
    expect(backgroundImage).toContain('images.unsplash.com');

    const titleSize = await page.getByTestId('home-session-greeting').evaluate((node) => {
      return Number.parseFloat(globalThis.getComputedStyle(node).fontSize);
    });
    expect(titleSize).toBeGreaterThanOrEqual(56);
  });

  test('logged-in user can open countdown from homepage shortcut without login redirect', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await page.getByTestId('home-session-countdown').click();

    await expect(page).toHaveURL(/\/countdown\/?$/);
    await expect(page).not.toHaveURL(/\/login\/\?next=/);
    await expect(page.getByTestId('countdown-main')).toBeVisible();
  });

  test('logged-in session persists on homepage refresh', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('home-session-panel')).toBeVisible();

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('home-session-panel')).toBeVisible();
    await expect(page.getByTestId('home-guest-actions')).toBeHidden();
  });
});
