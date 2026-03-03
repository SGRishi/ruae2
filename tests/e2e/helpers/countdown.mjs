import { readFile } from 'node:fs/promises';

const FIXTURE_1 = new URL('../../fixtures/scenery-1.png', import.meta.url);
const FIXTURE_2 = new URL('../../fixtures/scenery-2.png', import.meta.url);

let cachedFixtures = null;

async function loadFixtures() {
  if (cachedFixtures) return cachedFixtures;
  const [first, second] = await Promise.all([readFile(FIXTURE_1), readFile(FIXTURE_2)]);
  cachedFixtures = [first, second];
  return cachedFixtures;
}

export async function installCountdownTestClock(page, options = {}) {
  const controls = {
    nowMs: options.nowMs ?? Date.UTC(2026, 0, 1, 12, 0, 0),
    tickIntervalMs: options.tickIntervalMs ?? 80,
    tickStepMs: options.tickStepMs ?? 1_000,
    backgroundIntervalMs: options.backgroundIntervalMs ?? 240,
  };

  await page.addInitScript((payload) => {
    window.__COUNTDOWN_TEST__ = payload;
  }, controls);
}

export async function stubBackgroundImages(page) {
  const [first, second] = await loadFixtures();
  let calls = 0;

  await page.route('https://images.unsplash.com/**', async (route) => {
    const body = calls % 2 === 0 ? first : second;
    calls += 1;
    await route.fulfill({
      status: 200,
      contentType: 'image/png',
      body,
      headers: {
        'cache-control': 'public, max-age=600',
      },
    });
  });

  return {
    getCalls() {
      return calls;
    },
  };
}

export async function createTimer(page, options = {}) {
  const {
    minutes = 10,
    isPublic = false,
    expectShareUrl = true,
  } = options;

  const durationInput = page.getByTestId('duration-minutes');
  const privacyToggle = page.getByTestId('privacy-toggle');
  const submit = page.getByTestId('create-timer-button');
  const shareUrlInput = page.getByTestId('share-url');

  await durationInput.fill(String(minutes));

  if (isPublic !== (await privacyToggle.isChecked())) {
    await privacyToggle.click();
  }

  await submit.click();

  if (!expectShareUrl) return '';

  await page.waitForFunction((selector) => {
    const input = document.querySelector(selector);
    return Boolean(input && input.value && /^https?:\/\//i.test(input.value));
  }, '[data-testid="share-url"]');
  return shareUrlInput.inputValue();
}

export function toPathnameAndSearch(urlValue) {
  const url = new URL(urlValue);
  return `${url.pathname}${url.search}`;
}
