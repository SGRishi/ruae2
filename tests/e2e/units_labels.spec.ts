import { expect, test } from '@playwright/test';
import { installCountdownTestClock, stubBackgroundImages } from './helpers/countdown';

test.describe('units labels', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('labels exist and are above numeric values', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('label-days')).toHaveText(/days/i);
    await expect(page.getByTestId('label-hours')).toHaveText(/hours/i);
    await expect(page.getByTestId('label-minutes')).toHaveText(/minutes/i);
    await expect(page.getByTestId('label-seconds')).toHaveText(/seconds/i);

    const orderIsValid = await page.evaluate(() => {
      const units = ['days', 'hours', 'minutes', 'seconds'];
      return units.every((unit) => {
        const label = document.querySelector(`[data-testid="label-${unit}"]`);
        const value = document.querySelector(`[data-testid="countdown-${unit}"]`);
        if (!label || !value) return false;

        const labelRect = label.getBoundingClientRect();
        const valueRect = value.getBoundingClientRect();
        const domOrder = Boolean(label.compareDocumentPosition(value) & Node.DOCUMENT_POSITION_FOLLOWING);
        return domOrder && labelRect.top <= valueRect.top;
      });
    });

    expect(orderIsValid).toBe(true);
  });
});
