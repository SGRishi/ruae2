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

async function createIsolatedPage(browser, clockOptions = {}) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await installCountdownTestClock(page, clockOptions);
  await stubBackgroundImages(page);
  return { context, page };
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
      const style = globalThis.getComputedStyle(node);
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

    const fontSize = await clock.evaluate((node) =>
      Number.parseFloat(globalThis.getComputedStyle(node).fontSize)
    );
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

  test('6) creating share URL returns unique URLs, and copy-paste view shows same countdown', async ({
    page,
    browser,
  }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const firstUrl = await createTimer(page, { minutes: 12, isPublic: true });
    const secondUrl = await createTimer(page, { minutes: 13, isPublic: true });

    expect(firstUrl).not.toEqual(secondUrl);
    expect(firstUrl).toContain('/countdown/');
    expect(secondUrl).toContain('/countdown/');

    const ownerSeconds = parseHms(
      (await page.getByTestId('countdown-clock').textContent())?.trim()
    );
    expect(ownerSeconds).not.toBeNull();

    const viewer = await createIsolatedPage(browser);
    await viewer.page.goto(toPathnameAndSearch(secondUrl), { waitUntil: 'domcontentloaded' });
    await expect(viewer.page.getByTestId('timer-error')).toBeHidden();
    await expect(viewer.page.getByTestId('countdown-clock')).toBeVisible();

    const viewerSeconds = parseHms(
      (await viewer.page.getByTestId('countdown-clock').textContent())?.trim()
    );
    expect(viewerSeconds).not.toBeNull();
    expect(Math.abs(ownerSeconds - viewerSeconds)).toBeLessThanOrEqual(2);

    await viewer.page.goto(toPathnameAndSearch(firstUrl), { waitUntil: 'domcontentloaded' });
    await expect(viewer.page.getByTestId('timer-error')).toBeHidden();
    await viewer.context.close();
  });

  test('7) private/public behavior and toggle persistence', async ({ page, browser }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const privateUrl = await createTimer(page, { minutes: 20, isPublic: false });
    expect(privateUrl).toContain('?token=');

    const privateWithoutToken = new URL(privateUrl);
    privateWithoutToken.search = '';

    const privateViewer = await createIsolatedPage(browser);
    await privateViewer.page.goto(`${privateWithoutToken.pathname}`, {
      waitUntil: 'domcontentloaded',
    });
    await expect(privateViewer.page.getByTestId('timer-error')).toContainText(/private/i);
    const privateRobots = await privateViewer.page
      .locator('meta[name="robots"]')
      .getAttribute('content');
    expect(privateRobots).toMatch(/noindex/i);

    await privateViewer.page.goto(toPathnameAndSearch(privateUrl), {
      waitUntil: 'domcontentloaded',
    });
    await expect(privateViewer.page.getByTestId('timer-error')).toBeHidden();
    await privateViewer.context.close();

    await expect(page.getByTestId('privacy-toggle')).not.toBeChecked();
    await page.getByTestId('privacy-toggle').click();
    await expect(page.getByTestId('privacy-toggle')).toBeChecked();
    await expect(page.getByTestId('share-url')).not.toHaveValue(/\?token=/);
    const publicUrl = await page.getByTestId('share-url').inputValue();
    expect(publicUrl).not.toContain('?token=');

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('privacy-toggle')).toBeChecked();

    const publicViewer = await createIsolatedPage(browser);
    await publicViewer.page.goto(toPathnameAndSearch(publicUrl), { waitUntil: 'domcontentloaded' });
    await expect(publicViewer.page.getByTestId('timer-error')).toBeHidden();
    const publicRobots = await publicViewer.page
      .locator('meta[name="robots"]')
      .getAttribute('content');
    expect(publicRobots).toMatch(/index/i);
    await publicViewer.context.close();
  });

  test('8) background transitions on schedule', async ({ page }) => {
    await installCountdownTestClock(page, { backgroundIntervalMs: 110 });
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const background = page.getByTestId('background');
    const initial = await background.evaluate(
      (node) => globalThis.getComputedStyle(node).backgroundImage
    );

    await expect
      .poll(
        () => background.evaluate((node) => globalThis.getComputedStyle(node).backgroundImage),
        { timeout: 4_000 }
      )
      .not.toEqual(initial);
  });

  test('9) accessibility smoke: heading, text color, keyboard reachability', async ({ page }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    await expect(page.locator('h1')).toHaveCount(1);
    const clockColor = await page
      .getByTestId('countdown-clock')
      .evaluate((node) => globalThis.getComputedStyle(node).color);
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
            if (
              await page
                .getByTestId('privacy-toggle')
                .evaluate((el) => el === globalThis.document.activeElement)
            ) {
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
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const serverNow = Date.now();
    const create = await page.request.post('/api/countdown/timer', {
      data: {
        deadlineMs: serverNow + 1_500,
        isPublic: true,
      },
    });
    expect(create.ok()).toBe(true);
    const created = await create.json();
    expect(created?.ok).toBe(true);
    const timerId = String(created?.timer?.id || '');
    expect(timerId.length).toBeGreaterThan(0);
    const validUrl = `/countdown/${encodeURIComponent(timerId)}`;

    await page.goto('/countdown/does-not-exist', { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toContainText(/invalid/i);

    await page.goto(validUrl, { waitUntil: 'domcontentloaded' });
    await expect(page.getByTestId('timer-error')).toBeHidden();

    await expect
      .poll(
        async () => {
          const response = await page.request.get(
            `/api/countdown/timer?id=${encodeURIComponent(timerId)}`
          );
          const data = await response.json();
          return Boolean(data?.expired);
        },
        { timeout: 10_000 }
      )
      .toBe(true);

    await page.goto(validUrl, { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('timer-error')).toContainText(/expired/i);
    await expect(page.getByTestId('countdown-main')).toBeVisible();
  });

  test('13) fallback route restore from /countdown/index.html?r=... keeps tokenized links working', async ({
    page,
  }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });
    const shareUrl = await createTimer(page, { minutes: 9, isPublic: false });
    const restoredPath = toPathnameAndSearch(shareUrl);

    await page.goto(`/countdown/index.html?r=${encodeURIComponent(restoredPath)}`, {
      waitUntil: 'domcontentloaded',
    });

    await expect(page).toHaveURL(new RegExp(restoredPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    await expect(page.getByTestId('timer-error')).toBeHidden();
    await expect(page.getByTestId('countdown-clock')).toBeVisible();
  });

  test('14) embed URL renders countdown without editor controls', async ({ page, browser }) => {
    await page.goto('/countdown/', { waitUntil: 'domcontentloaded' });

    const publicUrl = await createTimer(page, { minutes: 11, isPublic: true });
    const ownerSeconds = parseHms(
      (await page.getByTestId('countdown-clock').textContent())?.trim()
    );
    expect(ownerSeconds).not.toBeNull();

    const embedUrl = new URL(publicUrl);
    embedUrl.searchParams.set('embed', '1');

    const viewer = await createIsolatedPage(browser);
    await viewer.page.goto(toPathnameAndSearch(embedUrl.toString()), {
      waitUntil: 'domcontentloaded',
    });

    await expect(viewer.page.locator('body')).toHaveClass(/countdown-embed/);
    await expect(viewer.page.getByTestId('countdown-clock')).toBeVisible();
    await expect(viewer.page.getByTestId('timer-form')).toBeHidden();
    await expect(viewer.page.getByTestId('share-url')).toBeHidden();

    const viewerSeconds = parseHms(
      (await viewer.page.getByTestId('countdown-clock').textContent())?.trim()
    );
    expect(viewerSeconds).not.toBeNull();
    expect(Math.abs(ownerSeconds - viewerSeconds)).toBeLessThanOrEqual(2);

    await viewer.context.close();
  });

  test('15) shared URL keeps elapsed time in sync (10:00 -> about 09:30 after 30 seconds)', async ({
    browser,
  }) => {
    test.setTimeout(120_000);

    const ownerContext = await browser.newContext();
    const ownerPage = await ownerContext.newPage();
    await stubBackgroundImages(ownerPage);

    await ownerPage.goto('/countdown/', { waitUntil: 'domcontentloaded' });
    const shareUrl = await createTimer(ownerPage, { minutes: 10, isPublic: true });

    await expect
      .poll(
        async () =>
          parseHms((await ownerPage.getByTestId('countdown-clock').textContent())?.trim()),
        { timeout: 45_000 }
      )
      .toBeLessThanOrEqual(570);

    const ownerSeconds = parseHms(
      (await ownerPage.getByTestId('countdown-clock').textContent())?.trim()
    );
    expect(ownerSeconds).not.toBeNull();
    expect(ownerSeconds).toBeGreaterThanOrEqual(565);
    expect(ownerSeconds).toBeLessThanOrEqual(570);

    const viewerContext = await browser.newContext();
    const viewerPage = await viewerContext.newPage();
    await stubBackgroundImages(viewerPage);

    await viewerPage.goto(toPathnameAndSearch(shareUrl), { waitUntil: 'domcontentloaded' });
    await expect(viewerPage.getByTestId('timer-error')).toBeHidden();

    const viewerSeconds = parseHms(
      (await viewerPage.getByTestId('countdown-clock').textContent())?.trim()
    );
    expect(viewerSeconds).not.toBeNull();
    expect(viewerSeconds).toBeGreaterThanOrEqual(565);
    expect(viewerSeconds).toBeLessThanOrEqual(572);
    expect(Math.abs(ownerSeconds - viewerSeconds)).toBeLessThanOrEqual(2);

    await ownerContext.close();
    await viewerContext.close();
  });
});
