import { expect, test } from '@playwright/test';
import { createCountdown, installCountdownTestClock, stubBackgroundImages } from './helpers/countdown';

test.describe('progress bar', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page, { nowMs: Date.UTC(2026, 0, 1, 12, 0, 0) });
    await stubBackgroundImages(page);
  });

  test('progress exists and stays in 0-100 range', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    const endAtMs = Date.now() + 3 * 60 * 60 * 1000;

    await createCountdown(page, {
      title: 'Progress test',
      endAtMs,
      mode: 'public',
    });
    await expect(page.getByTestId('public-url')).toHaveValue(/\/countdown\//);

    const first = Number.parseInt(
      String((await page.getByTestId('progress-bar').getAttribute('aria-valuenow')) || '0'),
      10
    );

    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThanOrEqual(100);

    await expect
      .poll(async () => {
        return String((await page.getByTestId('progress-bar').evaluate((node) => node.style.width)) || '');
      })
      .toMatch(/%/);

    const current = await page.evaluate(() => {
      const bar = document.querySelector('[data-testid="progress-bar"]');
      const percent = document.querySelector('[data-testid="progress-percent"]');
      return {
        valueNow: Number.parseInt(String(bar?.getAttribute('aria-valuenow') || '0'), 10),
        percent: Number.parseFloat(String(percent?.textContent || '0').replace('%', '')),
      };
    });

    expect(current.valueNow).toBeGreaterThanOrEqual(0);
    expect(current.valueNow).toBeLessThanOrEqual(100);
    expect(current.percent).toBeGreaterThanOrEqual(0);
    expect(current.percent).toBeLessThanOrEqual(100);

    const second = Number.parseInt(
      String((await page.getByTestId('progress-bar').getAttribute('aria-valuenow')) || '0'),
      10
    );

    expect(second).toBeLessThanOrEqual(first);
  });
});
