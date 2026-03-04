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

  test('visibility checkboxes are mutually exclusive and unit rows are left aligned', async ({
    page,
  }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    const publicBox = page.getByTestId('public-checkbox');
    const privateBox = page.getByTestId('private-checkbox');

    await expect(privateBox).toBeChecked();
    await publicBox.check();
    await expect(publicBox).toBeChecked();
    await expect(privateBox).not.toBeChecked();

    await privateBox.check();
    await expect(privateBox).toBeChecked();
    await expect(publicBox).not.toBeChecked();

    const fieldset = page.locator('.units-fieldset');
    const unitRow = page.locator('label[for="unitsSeconds"]');
    const rowText = unitRow.locator('.inline-text');
    const rowCheckbox = unitRow.locator('input[type="checkbox"]');

    const [fieldBox, rowBox, textBox, checkboxBox] = await Promise.all([
      fieldset.boundingBox(),
      unitRow.boundingBox(),
      rowText.boundingBox(),
      rowCheckbox.boundingBox(),
    ]);

    expect(fieldBox).not.toBeNull();
    expect(rowBox).not.toBeNull();
    expect(textBox).not.toBeNull();
    expect(checkboxBox).not.toBeNull();

    if (fieldBox && rowBox && textBox && checkboxBox) {
      expect(rowBox.x - fieldBox.x).toBeLessThanOrEqual(36);
      expect(textBox.x).toBeLessThan(checkboxBox.x);
      expect(checkboxBox.x - (textBox.x + textBox.width)).toBeLessThanOrEqual(36);
    }
  });
});
