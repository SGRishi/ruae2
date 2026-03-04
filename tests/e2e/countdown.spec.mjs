import { test, expect } from '@playwright/test';
import {
  installCountdownTestClock,
  stubBackgroundImages,
  createTimer,
  toPathnameAndSearch,
  forceNextBackground,
} from './helpers/countdown.mjs';

function formatDatetimeLocal(epochMs) {
  const date = new Date(epochMs);
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

async function countdownTotalSeconds(page) {
  const [daysText, hoursText, minutesText, secondsText] = await Promise.all([
    page.getByTestId('countdown-days').textContent(),
    page.getByTestId('countdown-hours').textContent(),
    page.getByTestId('countdown-minutes').textContent(),
    page.getByTestId('countdown-seconds').textContent(),
  ]);

  const days = Number.parseInt(String(daysText || '0'), 10) || 0;
  const hours = Number.parseInt(String(hoursText || '0'), 10) || 0;
  const minutes = Number.parseInt(String(minutesText || '0'), 10) || 0;
  const seconds = Number.parseInt(String(secondsText || '0'), 10) || 0;
  return days * 86_400 + hours * 3_600 + minutes * 60 + seconds;
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

  test('future datetime updates immediately, labels are above values, and progress is valid', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    const deadlineValue = await page.evaluate(() => {
      const nowMs = globalThis.__COUNTDOWN_TEST_API__?.nowMs?.() ?? Date.now();
      return nowMs + 5 * 60 * 1000;
    });

    await page.getByTestId('deadline-input').fill(formatDatetimeLocal(deadlineValue));
    await page.getByTestId('visibility-toggle').check();
    await page.getByTestId('create-button').click();

    await expect(page.getByTestId('public-url')).toHaveValue(/\/countdown\//);

    const initialSeconds = await countdownTotalSeconds(page);
    await expect
      .poll(() => countdownTotalSeconds(page), { timeout: 4_000 })
      .toBeLessThan(initialSeconds);

    await expect(page.getByTestId('label-days')).toHaveText(/days/i);
    await expect(page.getByTestId('label-hours')).toHaveText(/hours/i);
    await expect(page.getByTestId('label-minutes')).toHaveText(/minutes/i);
    await expect(page.getByTestId('label-seconds')).toHaveText(/seconds/i);

    const labelsAboveValues = await page.evaluate(() => {
      const pairs = [
        ['label-days', 'countdown-days'],
        ['label-hours', 'countdown-hours'],
        ['label-minutes', 'countdown-minutes'],
        ['label-seconds', 'countdown-seconds'],
      ];

      return pairs.every(([labelId, valueId]) => {
        const label = document.querySelector(`[data-testid="${labelId}"]`);
        const value = document.querySelector(`[data-testid="${valueId}"]`);
        if (!label || !value) return false;
        const labelRect = label.getBoundingClientRect();
        const valueRect = value.getBoundingClientRect();
        return labelRect.top < valueRect.top;
      });
    });
    expect(labelsAboveValues).toBe(true);

    const progressInfo = await page.getByTestId('progress-bar').evaluate((node) => ({
      width: node.style.width,
      valueNow: Number.parseInt(node.getAttribute('aria-valuenow') || '0', 10),
    }));

    expect(progressInfo.width).toMatch(/%/);
    expect(progressInfo.valueNow).toBeGreaterThanOrEqual(0);
    expect(progressInfo.valueNow).toBeLessThanOrEqual(100);
  });

  test('ambient player uses ClassicFM stream and enters play or blocked state', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    const streamSrc = await page.getByTestId('audio-element').getAttribute('src');
    expect(streamSrc).toBe('https://ice-the.musicradio.com/ClassicFMMP3');

    await page.getByTestId('music-play').click();

    await expect
      .poll(async () => {
        const paused = await page.getByTestId('audio-element').evaluate((el) => el.paused);
        const status = String((await page.getByTestId('audio-status').textContent()) || '');
        return !paused || /playing|blocked/i.test(status);
      })
      .toBe(true);

    await page.getByTestId('music-pause').click();
    await expect
      .poll(() => page.getByTestId('audio-element').evaluate((el) => el.paused))
      .toBe(true);
  });

  test('background container exists, has overlay, and changes on forced tick', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('bg-image')).toBeVisible();
    await expect(page.getByTestId('overlay')).toBeVisible();

    const firstUrl = await page.getByTestId('bg-image').evaluate((node) => node.dataset.backgroundUrl || '');
    await forceNextBackground(page);

    await expect
      .poll(() => page.getByTestId('bg-image').evaluate((node) => node.dataset.backgroundUrl || ''))
      .not.toEqual(firstUrl);
  });

  test('public URL, private URL password gate, embed view, and sync across contexts', async ({
    page,
    browser,
  }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('make-public-button')).toBeVisible();

    const publicShareUrl = await createTimer(page, { minutes: 12, isPublic: true, returnField: 'public-url' });
    const embedUrl = await page.getByTestId('embed-url').inputValue();

    const viewerA = await createIsolatedPage(browser);
    await viewerA.page.goto(toPathnameAndSearch(publicShareUrl), { waitUntil: 'domcontentloaded' });
    await expect(viewerA.page.getByTestId('countdown-display')).toBeVisible();

    const viewerB = await createIsolatedPage(browser);
    await viewerB.page.goto(toPathnameAndSearch(publicShareUrl), { waitUntil: 'domcontentloaded' });
    await expect(viewerB.page.getByTestId('countdown-display')).toBeVisible();

    const [secondsA, secondsB] = await Promise.all([
      countdownTotalSeconds(viewerA.page),
      countdownTotalSeconds(viewerB.page),
    ]);
    expect(Math.abs(secondsA - secondsB)).toBeLessThanOrEqual(2);

    const embedViewer = await createIsolatedPage(browser);
    await embedViewer.page.goto(toPathnameAndSearch(embedUrl), { waitUntil: 'domcontentloaded' });
    await expect(embedViewer.page.getByTestId('countdown-display')).toBeVisible();
    await expect(embedViewer.page.getByTestId('timer-form')).toBeHidden();

    const privatePassword = 'StrongPassword123';
    const privateUrl = await createTimer(page, {
      minutes: 9,
      isPublic: false,
      password: privatePassword,
      returnField: 'private-url',
    });

    const privateViewer = await createIsolatedPage(browser);
    await privateViewer.page.goto(toPathnameAndSearch(privateUrl), { waitUntil: 'domcontentloaded' });
    await expect(privateViewer.page.getByTestId('password-input')).toBeVisible();

    await privateViewer.page.getByTestId('password-input').fill('WrongPassword123');
    await privateViewer.page.getByTestId('password-submit').click();
    await expect(privateViewer.page.getByTestId('password-message')).toContainText(/access denied|incorrect/i);

    await privateViewer.page.getByTestId('password-input').fill(privatePassword);
    await privateViewer.page.getByTestId('password-submit').click();
    await expect(privateViewer.page.getByTestId('password-gate')).toBeHidden();
    await expect(privateViewer.page.getByTestId('countdown-display')).toBeVisible();

    await Promise.all([
      viewerA.context.close(),
      viewerB.context.close(),
      embedViewer.context.close(),
      privateViewer.context.close(),
    ]);
  });
});
