import { readFile } from 'node:fs/promises';
import { Page } from '@playwright/test';

const FIXTURE_1 = new URL('../../fixtures/scenery-1.png', import.meta.url);
const FIXTURE_2 = new URL('../../fixtures/scenery-2.png', import.meta.url);

let cachedFixtures: [Buffer, Buffer] | null = null;

async function loadFixtures(): Promise<[Buffer, Buffer]> {
  if (cachedFixtures) return cachedFixtures;
  const [first, second] = await Promise.all([readFile(FIXTURE_1), readFile(FIXTURE_2)]);
  cachedFixtures = [first, second];
  return cachedFixtures;
}

export async function installCountdownTestClock(
  page: Page,
  options: {
    nowMs?: number;
    tickIntervalMs?: number;
    tickStepMs?: number;
    backgroundIntervalMs?: number;
  } = {}
): Promise<void> {
  const controls = {
    nowMs: options.nowMs ?? Date.UTC(2026, 0, 1, 12, 0, 0),
    tickIntervalMs: options.tickIntervalMs ?? 80,
    tickStepMs: options.tickStepMs ?? 1000,
    backgroundIntervalMs: options.backgroundIntervalMs ?? 60_000,
    nodeEnv: 'test',
  };

  await page.addInitScript((payload) => {
    (globalThis as any).__COUNTDOWN_TEST__ = payload;
  }, controls);
}

export async function stubBackgroundImages(page: Page): Promise<void> {
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
}

function two(value: number): string {
  return String(value).padStart(2, '0');
}

function ukDateTimeFields(epochMs: number): { date: string; time: string } {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/London',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  const parts = formatter.formatToParts(new Date(epochMs));
  const map = Object.fromEntries(parts.map((part) => [part.type, part.value]));

  const day = Number.parseInt(String(map.day || '0'), 10);
  const month = Number.parseInt(String(map.month || '0'), 10);
  const year = Number.parseInt(String(map.year || '0'), 10);
  const hour = Number.parseInt(String(map.hour || '0'), 10);
  const minute = Number.parseInt(String(map.minute || '0'), 10);

  return {
    date: `${two(day)}/${two(month)}/${String(year).padStart(4, '0')}`,
    time: `${two(hour)}:${two(minute)}`,
  };
}

export async function fillDeadlineFromEpoch(page: Page, epochMs: number): Promise<void> {
  const fields = ukDateTimeFields(epochMs);
  await page.getByTestId('deadline-date').fill(fields.date);
  await page.getByTestId('deadline-time').fill(fields.time);
}

export async function setUnits(
  page: Page,
  units: Partial<Record<'days' | 'hours' | 'minutes' | 'seconds', boolean>>
): Promise<void> {
  for (const unit of ['days', 'hours', 'minutes', 'seconds'] as const) {
    if (!Object.prototype.hasOwnProperty.call(units, unit)) continue;
    const nextValue = Boolean(units[unit]);
    const input = page.getByTestId(`units-${unit}`);
    const current = await input.isChecked();
    if (current !== nextValue) {
      await input.click();
    }
  }
}

export async function setVisibility(page: Page, mode: 'public' | 'private'): Promise<void> {
  const publicBox = page.getByTestId('public-checkbox');
  const privateBox = page.getByTestId('private-checkbox');

  const shouldPublic = mode === 'public';
  const shouldPrivate = mode === 'private';

  if ((await publicBox.isChecked()) !== shouldPublic) {
    await publicBox.click();
  }
  if ((await privateBox.isChecked()) !== shouldPrivate) {
    await privateBox.click();
  }
}

export async function createCountdown(
  page: Page,
  options: {
    title?: string;
    endAtMs: number;
    mode: 'public' | 'private';
    password?: string;
    units?: Partial<Record<'days' | 'hours' | 'minutes' | 'seconds', boolean>>;
  }
): Promise<void> {
  await page.getByTestId('title-input').fill(options.title || 'Test countdown');
  await fillDeadlineFromEpoch(page, options.endAtMs);

  if (options.units) {
    await setUnits(page, options.units);
  }

  await setVisibility(page, options.mode);

  if (options.mode === 'private') {
    await page.getByTestId('setup-password-input').fill(options.password || 'StrongPassword123');
  }

  await page.getByTestId('create-button').click();
}

export async function totalSeconds(page: Page): Promise<number> {
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

export function toPathnameAndSearch(urlValue: string): string {
  const raw = String(urlValue || '').trim();
  if (!raw) {
    throw new Error('Expected URL or iframe snippet but received an empty value.');
  }

  let candidate = raw;
  if (raw.startsWith('<')) {
    const srcMatch = raw.match(/src\s*=\s*"([^"]+)"/i) || raw.match(/src\s*=\s*'([^']+)'/i);
    candidate = srcMatch?.[1] || '';
  }

  if (!candidate) {
    throw new Error(`Unable to parse iframe src from value: ${raw}`);
  }

  const url = new URL(candidate);
  return `${url.pathname}${url.search}`;
}
