import { test, expect } from '@playwright/test';
import { QA_SESSIONS } from '../fixtures/maths-env.mjs';
import { setSessionCookie } from './helpers/session.mjs';
import {
  installCountdownTestClock,
  stubBackgroundImages,
  createTimer,
  toPathnameAndSearch,
} from '../../tests/e2e/helpers/countdown.mjs';

test.describe('countdown authenticated access', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('approved logged-in user can access /countdown and use timer controls', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    await expect(page).not.toHaveURL(/\/login\/\?next=/);
    await expect(page.getByTestId('countdown-main')).toBeVisible();
    await expect(page.getByTestId('countdown-clock')).toBeVisible();

    await page.getByTestId('duration-minutes').fill('15');
    await page.getByTestId('create-timer-button').click();
    await expect(page.getByTestId('share-url')).toHaveValue(/\/countdown\//);
    await expect(page.getByTestId('timer-error')).toBeHidden();
  });

  test('pending logged-in user can still access /countdown (not approval-gated)', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.pending.token);

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    await expect(page).not.toHaveURL(/\/login\/\?next=/);
    await expect(page.getByTestId('countdown-main')).toBeVisible();
    await expect(page.getByTestId('timer-form')).toBeVisible();
  });

  test('logged-in user can create timer and open share URL without auth redirect', async ({ page, context }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    const shareUrl = await createTimer(page, { minutes: 8, isPublic: true });

    await page.goto(toPathnameAndSearch(shareUrl), { waitUntil: 'domcontentloaded' });
    await expect(page).not.toHaveURL(/\/login\/\?next=/);
    await expect(page.getByTestId('countdown-clock')).toBeVisible();
    await expect(page.getByTestId('timer-error')).toBeHidden();
  });

  test('logged-in user can create public URL that works for anonymous viewers', async ({
    page,
    context,
    browser,
  }) => {
    await setSessionCookie(context, QA_SESSIONS.approved.token);

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    const shareUrl = await createTimer(page, { minutes: 14, isPublic: true });
    expect(shareUrl).not.toContain('?token=');

    const anonContext = await browser.newContext();
    const anonPage = await anonContext.newPage();
    await installCountdownTestClock(anonPage);
    await stubBackgroundImages(anonPage);
    await anonPage.goto(toPathnameAndSearch(shareUrl), { waitUntil: 'domcontentloaded' });

    await expect(anonPage).not.toHaveURL(/\/login\/\?next=/);
    await expect(anonPage.getByTestId('countdown-main')).toBeVisible();
    await expect(anonPage.getByTestId('timer-error')).toBeHidden();

    await anonContext.close();
  });
});
