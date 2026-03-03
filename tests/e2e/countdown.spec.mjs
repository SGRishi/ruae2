import { test, expect } from '@playwright/test';
import {
  installCountdownTestClock,
  stubBackgroundImages,
  createTimer,
  toPathnameAndSearch,
} from './helpers/countdown.mjs';

function parseHms(value) {
  const match = String(value || '')
    .trim()
    .match(/^(\d+):(\d{2}):(\d{2})$/);
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  const seconds = Number(match[3]);
  return hours * 3600 + minutes * 60 + seconds;
}

test.describe('countdown route', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('1) page loads with background, overlay, and clock', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('background')).toBeVisible();
    await expect(page.getByTestId('overlay')).toBeVisible();
    await expect(page.getByTestId('countdown-clock')).toBeVisible();
    await expect(page.getByTestId('timer-form')).toBeVisible();
  });

  test('2) dark overlay is present and readable', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const overlayStyle = await page.getByTestId('overlay').evaluate((node) => {
      const style = window.getComputedStyle(node);
      return {
        backgroundColor: style.backgroundColor,
        opacity: style.opacity,
      };
    });

    expect(overlayStyle.backgroundColor).toContain('rgba');
    const opacity = Number.parseFloat(overlayStyle.opacity);
    expect(Number.isFinite(opacity)).toBe(true);
    expect(opacity).toBeGreaterThanOrEqual(0.95);
  });

  test('3) clock is centered and visually large', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const clock = page.getByTestId('countdown-clock');
    const box = await clock.boundingBox();
    const viewport = page.viewportSize();
    expect(box).not.toBeNull();
    expect(viewport).not.toBeNull();

    const centerX = box.x + box.width / 2;
    const centerY = box.y + box.height / 2;
    expect(Math.abs(centerX - viewport.width / 2)).toBeLessThan(viewport.width * 0.2);
    expect(Math.abs(centerY - viewport.height / 2)).toBeLessThan(viewport.height * 0.33);

    const fontSize = await clock.evaluate((node) => Number.parseFloat(window.getComputedStyle(node).fontSize));
    expect(fontSize).toBeGreaterThanOrEqual(48);
  });

  test('4) countdown ticks down deterministically', async ({ page }) => {
    await installCountdownTestClock(page, {
      tickIntervalMs: 50,
      tickStepMs: 1_000,
    });
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    await createTimer(page, { minutes: 3 });
    const clock = page.getByTestId('countdown-clock');
    const initial = (await clock.textContent())?.trim();

    await expect
      .poll(
        async () => {
          const value = (await clock.textContent())?.trim();
          return parseHms(value);
        },
        { timeout: 4_000 }
      )
      .toBeLessThan(parseHms(initial));
  });

  test('5) setting timer updates displayed countdown', async ({ page }) => {
    await installCountdownTestClock(page, {
      tickIntervalMs: 5_000,
      tickStepMs: 1_000,
    });
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    await createTimer(page, { minutes: 10 });
    const value = (await page.getByTestId('countdown-clock').textContent())?.trim();
    const totalSeconds = parseHms(value);
    expect(totalSeconds).toBeGreaterThanOrEqual(9 * 60);
    expect(totalSeconds).toBeLessThanOrEqual(10 * 60);
  });

  test('6) creating share URL returns unique URLs and each loads', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const firstUrl = await createTimer(page, { minutes: 12 });
    const secondUrl = await createTimer(page, { minutes: 13 });

    expect(firstUrl).not.toEqual(secondUrl);
    expect(firstUrl).toContain('/countdown/');
    expect(secondUrl).toContain('/countdown/');

    await page.goto(toPathnameAndSearch(firstUrl), { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toBeHidden();
    await expect(page.getByTestId('countdown-clock')).toBeVisible();
  });

  test('7) private/public behavior and toggle persistence', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const privateUrl = await createTimer(page, { minutes: 20, isPublic: false });
    expect(privateUrl).toContain('?token=');

    const privateWithoutToken = new URL(privateUrl);
    privateWithoutToken.search = '';
    await page.goto(`${privateWithoutToken.pathname}`, { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toContainText(/private/i);

    const privateRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(privateRobots).toMatch(/noindex/i);

    await page.goto(toPathnameAndSearch(privateUrl), { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toBeHidden();
    await expect(page.getByTestId('privacy-toggle')).not.toBeChecked();

    await page.getByTestId('privacy-toggle').click();
    await expect(page.getByTestId('privacy-toggle')).toBeChecked();
    const publicUrl = await page.getByTestId('share-url').inputValue();
    expect(publicUrl).not.toContain('?token=');

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('privacy-toggle')).toBeChecked();
    await page.goto(toPathnameAndSearch(publicUrl), { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toBeHidden();
    const publicRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(publicRobots).toMatch(/index/i);
  });

  test('8) background transitions on schedule', async ({ page }) => {
    await installCountdownTestClock(page, { backgroundIntervalMs: 110 });
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const background = page.getByTestId('background');
    const initial = await background.evaluate((node) => window.getComputedStyle(node).backgroundImage);

    await expect
      .poll(
        () => background.evaluate((node) => window.getComputedStyle(node).backgroundImage),
        { timeout: 4_000 }
      )
      .not.toEqual(initial);
  });

  test('9) accessibility smoke: heading, text color, keyboard reachability', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    await expect(page.locator('h1')).toHaveCount(1);
    const clockColor = await page
      .getByTestId('countdown-clock')
      .evaluate((node) => window.getComputedStyle(node).color);
    expect(clockColor).toBe('rgb(255, 255, 255)');
    await expect(page.getByTestId('overlay')).toBeVisible();

    await page.locator('body').focus();
    await page.keyboard.press('Tab');
    await expect(page.getByTestId('duration-minutes')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByTestId('deadline-input')).toBeFocused();
    await expect
      .poll(
        async () => {
          for (let step = 0; step < 4; step += 1) {
            if (await page.getByTestId('privacy-toggle').evaluate((el) => el === document.activeElement)) {
              return true;
            }
            await page.keyboard.press('Tab');
          }
          return false;
        },
        { timeout: 3_000 }
      )
      .toBe(true);
  });

  test('10) mobile viewport keeps clock visible and form usable', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const clock = page.getByTestId('countdown-clock');
    await expect(clock).toBeVisible();
    const box = await clock.boundingBox();
    expect(box).not.toBeNull();
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.y + box.height).toBeLessThanOrEqual(844);

    await expect(page.getByTestId('duration-minutes')).toBeVisible();
    await expect(page.getByTestId('create-timer-button')).toBeVisible();
  });

  test('11) audio exists and play control updates state after click', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const audio = page.getByTestId('audio-player');
    await expect(audio).toHaveCount(1);

    const sourceUrl = await audio.evaluate((node) => {
      const source = node.querySelector('source');
      return source?.src || node.currentSrc || node.src || '';
    });
    expect(sourceUrl).toMatch(/^https?:\/\//);

    const button = page.getByTestId('audio-play-button');
    await button.click();
    const state = await button.getAttribute('data-state');
    expect(['requested', 'playing', 'blocked']).toContain(state);
  });

  test('12) invalid and expired URLs show friendly errors without crash', async ({ page }) => {
    await installCountdownTestClock(page, {
      tickIntervalMs: 40,
      tickStepMs: 30_000,
    });
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    await createTimer(page, { minutes: 1, isPublic: true });
    await expect(page.getByTestId('timer-error')).toBeHidden();

    await page.goto('/countdown/does-not-exist', { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toContainText(/invalid/i);

    await page.evaluate(() => {
      const key = 'countdownTimers:v1';
      const raw = localStorage.getItem(key);
      const store = raw ? JSON.parse(raw) : {};
      store.expired_fixture = {
        id: 'expired_fixture',
        token: 'tok_fixture',
        isPublic: true,
        deadlineMs: 1,
        createdAtMs: 1,
      };
      localStorage.setItem(key, JSON.stringify(store));
    });

    await page.goto('/countdown/expired_fixture', { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toContainText(/expired/i);
    await expect(page.getByTestId('countdown-main')).toBeVisible();
  });
});
