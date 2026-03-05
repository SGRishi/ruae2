import { expect, test } from '@playwright/test';
import { installCountdownTestClock, stubBackgroundImages } from './helpers/countdown';

const EXPECTED_IDS = [
  '1470770841072-f978cf4d019e',
  '1469474968028-56623f02e42e',
  '1501785888041-af3ef285b470',
  '1500530855697-b586d89ba3ee',
  '1441974231531-c6227db76b6e',
  '1472396961693-142e6e269027',
  '1439066615861-d1af74d74000',
  '1482192596544-9eb780fc7f66',
  '1506744038136-46273834b3fb',
  '1507525428034-b723cf961d3e',
  '1464822759023-fed622ff2c3b',
  '1518837695005-2083093ee35b',
  '1465146344425-f00d5f5c8f07',
  '1418065460487-3e41a6c84dc5',
];

test.describe('background rotation', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('renders background + overlay and supports fixed slideshow sets with prev/next', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('bg-image')).toBeVisible();
    await expect(page.getByTestId('overlay')).toBeVisible();
    await expect(page.getByTestId('bg-prev')).toBeVisible();
    await expect(page.getByTestId('bg-next')).toBeVisible();
    await expect(page.getByTestId('slideshow-position')).toContainText(/slide 1 of/i);
    await expect(page.getByTestId('settings-menu-toggle')).toBeVisible();
    await page.getByTestId('settings-menu-toggle').click();
    await expect(page.getByTestId('theme-light-toggle')).toBeVisible();
    await expect(page.getByTestId('theme-dark-toggle')).toBeVisible();
    await expect(page.getByTestId('accent-blue')).toBeVisible();
    await expect(page.getByTestId('pack-light-toggle')).toBeVisible();
    await expect(page.getByTestId('pack-dark-toggle')).toBeVisible();

    await page.getByTestId('theme-light-toggle').click();
    await expect
      .poll(() =>
        page.evaluate(() => String((window as any).__COUNTDOWN_TEST_API__?.colorTheme?.() || ''))
      )
      .toEqual('light');
    await expect
      .poll(() => page.evaluate(() => String(document.body?.dataset?.colorTheme || '')))
      .toEqual('light');

    const shellBackgroundBeforeAccent = String(
      await page.locator('.countdown-shell').evaluate((node) => getComputedStyle(node).backgroundColor)
    );

    await page.getByTestId('settings-menu-toggle').click();
    await page.getByTestId('accent-blue').click();
    await expect
      .poll(() =>
        page.evaluate(() => String((window as any).__COUNTDOWN_TEST_API__?.accentPalette?.() || ''))
      )
      .toEqual('blue');
    await expect
      .poll(() =>
        page.evaluate(() => String(getComputedStyle(document.body).getPropertyValue('--accent') || '').trim())
      )
      .toEqual('#4fc3ff');
    await expect
      .poll(() =>
        page.locator('.countdown-shell').evaluate((node) => String(getComputedStyle(node).backgroundColor))
      )
      .not.toEqual(shellBackgroundBeforeAccent);

    const initialUrl = String(
      await page.getByTestId('bg-image').evaluate((node) => (node as HTMLElement).dataset.backgroundUrl || '')
    );
    expect(EXPECTED_IDS.some((id) => initialUrl.includes(id))).toBe(true);

    await page.getByTestId('settings-menu-toggle').click();
    await page.getByTestId('pack-dark-toggle').click();
    await expect
      .poll(() =>
        page.evaluate(() => String((window as any).__COUNTDOWN_TEST_API__?.backgroundPack?.() || ''))
      )
      .toEqual('dark');

    await page.getByTestId('settings-menu-toggle').click();
    await page.getByTestId('pack-light-toggle').click();
    await expect
      .poll(() =>
        page.evaluate(() => String((window as any).__COUNTDOWN_TEST_API__?.backgroundPack?.() || ''))
      )
      .toEqual('light');

    await page.getByTestId('settings-menu-toggle').click();
    await page.getByTestId('slideshow-size-input').fill('3');
    await page.getByTestId('slideshow-size-apply').click();
    await expect(page.getByTestId('slideshow-order-note')).toContainText(/order locked/i);
    await expect(page.getByTestId('slideshow-position')).toContainText('Slide 1 of 3');
    await expect
      .poll(() =>
        page.evaluate(() => Number((window as any).__COUNTDOWN_TEST_API__?.backgroundSetSize?.() || 0))
      )
      .toBe(3);

    const firstUrl = String(
      await page.getByTestId('bg-image').evaluate((node) => (node as HTMLElement).dataset.backgroundUrl || '')
    );

    await page.getByTestId('bg-next').click();
    await expect(page.getByTestId('slideshow-position')).toContainText('Slide 2 of 3');

    const secondUrl = String(
      await page.getByTestId('bg-image').evaluate((node) => (node as HTMLElement).dataset.backgroundUrl || '')
    );
    expect(secondUrl).not.toEqual(firstUrl);

    await page.getByTestId('bg-prev').click();
    await expect(page.getByTestId('slideshow-position')).toContainText('Slide 1 of 3');
    await expect
      .poll(() =>
        page.getByTestId('bg-image').evaluate((node) => (node as HTMLElement).dataset.backgroundUrl || '')
      )
      .toEqual(firstUrl);

    await page.getByTestId('settings-menu-toggle').click();
    await page.getByTestId('slide-jump-input').fill('3');
    await page.getByTestId('slide-jump-apply').click();
    await expect(page.getByTestId('slideshow-position')).toContainText('Slide 3 of 3');
    await expect(page.getByTestId('bg-next')).toBeDisabled();
  });
});
