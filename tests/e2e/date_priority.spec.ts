import { expect, test } from '@playwright/test';
import {
  createCountdown,
  installCountdownTestClock,
  stubBackgroundImages,
  totalSeconds,
} from './helpers/countdown';

test.describe('date priority', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page, { nowMs: Date.UTC(2026, 0, 1, 12, 0, 0) });
    await stubBackgroundImages(page);
  });

  test('uses selected future datetime and countdown ticks immediately', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    const endAtMs = Date.UTC(2030, 11, 25, 12, 0, 0);
    await createCountdown(page, {
      title: 'Christmas target',
      endAtMs,
      mode: 'public',
    });

    await expect(page.getByTestId('public-url')).toHaveValue(/\/countdown\//);

    const total = await totalSeconds(page);
    expect(total).toBeGreaterThan(60 * 60 * 24);

    const initialSeconds = Number.parseInt(
      String((await page.getByTestId('countdown-seconds').textContent()) || '0'),
      10
    );

    await expect
      .poll(async () => {
        const next = Number.parseInt(
          String((await page.getByTestId('countdown-seconds').textContent()) || '0'),
          10
        );
        return next !== initialSeconds;
      })
      .toBe(true);

    await expect(page.getByTestId('countdown-title')).toContainText('Christmas target');
  });
});
