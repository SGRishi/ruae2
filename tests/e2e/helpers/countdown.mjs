import { readFile } from 'node:fs/promises';

const FIXTURE_1 = new URL('../../fixtures/scenery-1.png', import.meta.url);
const FIXTURE_2 = new URL('../../fixtures/scenery-2.png', import.meta.url);
const DEFAULT_TEST_NOW_MS = Date.now() + 60 * 60 * 1000;

let cachedFixtures = null;

async function loadFixtures() {
  if (cachedFixtures) return cachedFixtures;
  const [first, second] = await Promise.all([readFile(FIXTURE_1), readFile(FIXTURE_2)]);
  cachedFixtures = [first, second];
  return cachedFixtures;
}

export async function installCountdownTestClock(page, options = {}) {
  const controls = {
    nowMs: options.nowMs ?? DEFAULT_TEST_NOW_MS,
    tickIntervalMs: options.tickIntervalMs ?? 80,
    tickStepMs: options.tickStepMs ?? 1_000,
    backgroundIntervalMs: options.backgroundIntervalMs ?? 240,
  };

  await page.addInitScript((payload) => {
    globalThis.__COUNTDOWN_TEST__ = payload;
  }, controls);
}

export async function advanceCountdownTestClock(page, ms) {
  await page.evaluate(
    (delta) => {
      const api = globalThis.__COUNTDOWN_TEST_API__;
      if (!api || typeof api.advance !== 'function') return;
      api.advance(delta);
    },
    Number(ms) || 0
  );
}

export async function forceNextBackground(page) {
  await page.evaluate(() => {
    const api = globalThis.__COUNTDOWN_TEST_API__;
    if (!api || typeof api.nextBackground !== 'function') return;
    api.nextBackground();
  });
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
    password = 'StrongPassword123',
    expectUrl = true,
    returnField = isPublic ? 'public-url' : 'private-url',
  } = options;

  const durationInput = page.getByTestId('duration-minutes');
  const visibilityToggle = page.getByTestId('visibility-toggle');
  const setupPassword = page.getByTestId('setup-password-input');
  const submit = page.getByTestId('create-button');
  const targetInput = page.getByTestId(returnField);
  const previousValue = await targetInput.inputValue();

  await durationInput.fill(String(minutes));

  if (isPublic !== (await visibilityToggle.isChecked())) {
    await visibilityToggle.click();
  }

  if (!isPublic) {
    await setupPassword.fill(password);
  }

  await submit.click();

  if (!expectUrl) return '';

  await page.waitForFunction(
    ({ selector, previous }) => {
      const input = globalThis.document.querySelector(selector);
      if (!input || !input.value || !/^https?:\/\//i.test(input.value)) return false;
      if (input.value === previous) return false;
      try {
        const url = new URL(input.value);
        const parts = url.pathname.split('/').filter(Boolean);
        return parts[0] === 'countdown' && parts.length >= 2;
      } catch {
        return false;
      }
    },
    { selector: `[data-testid="${returnField}"]`, previous: previousValue }
  );

  return targetInput.inputValue();
}

export function toPathnameAndSearch(urlValue) {
  const url = new URL(urlValue);
  return `${url.pathname}${url.search}`;
}
