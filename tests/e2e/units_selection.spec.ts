import { expect, test } from '@playwright/test';
import {
  createCountdown,
  fillDeadlineFromEpoch,
  installCountdownTestClock,
  setUnits,
  setVisibility,
  stubBackgroundImages,
} from './helpers/countdown';

test.describe('units selection', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page, { nowMs: Date.UTC(2026, 0, 1, 12, 0, 0) });
    await stubBackgroundImages(page);
  });

  test('carry-down works and validates against all units unchecked', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    const firstEndAtMs = Date.now() + 50 * 60 * 60 * 1000;

    await page.getByTestId('title-input').fill('Carry down test');
    await fillDeadlineFromEpoch(page, firstEndAtMs);
    await setVisibility(page, 'public');

    await setUnits(page, {
      days: false,
      hours: false,
      minutes: false,
      seconds: false,
    });

    await page.getByTestId('create-button').click();
    await expect(page.getByTestId('timer-error')).toContainText(/at least one unit/i);

    await setUnits(page, {
      days: false,
      hours: true,
      minutes: true,
      seconds: true,
    });

    await page.getByTestId('create-button').click();
    await expect(page.getByTestId('public-url')).toHaveValue(/\/countdown\//);

    await expect(page.locator('.countdown-unit[data-unit="days"]')).toBeHidden();
    await expect(page.locator('.countdown-unit[data-unit="hours"]')).toBeVisible();

    const hoursValue = Number.parseInt(
      String((await page.getByTestId('countdown-hours').textContent()) || '0'),
      10
    );
    expect(hoursValue).toBeGreaterThan(24);

    const secondEnd = Date.now() + 2 * 60 * 60 * 1000;
    await createCountdown(page, {
      title: 'Seconds only',
      endAtMs: secondEnd,
      mode: 'public',
      units: {
        days: false,
        hours: false,
        minutes: false,
        seconds: true,
      },
    });

    await expect(page.locator('.countdown-unit[data-unit="days"]')).toBeHidden();
    await expect(page.locator('.countdown-unit[data-unit="hours"]')).toBeHidden();
    await expect(page.locator('.countdown-unit[data-unit="minutes"]')).toBeHidden();
    await expect(page.locator('.countdown-unit[data-unit="seconds"]')).toBeVisible();

    const secondsOnlyValue = Number.parseInt(
      String((await page.getByTestId('countdown-seconds').textContent()) || '0'),
      10
    );
    expect(secondsOnlyValue).toBeGreaterThan(3600);
  });
});
