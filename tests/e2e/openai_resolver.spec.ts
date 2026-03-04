import { expect, test } from '@playwright/test';
import { installCountdownTestClock, stubBackgroundImages } from './helpers/countdown';

test.describe('openai date resolver', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('mocked resolver fills UK date/time and resolved display', async ({ page }) => {
    await page.route('**/api/resolve-event-date', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          isoUtc: '2026-05-05T08:00:00.000Z',
          display: 'Tuesday 5 May 2026, 09:00',
          confidence: 'high',
          notes: 'Mocked resolver result.',
          ambiguous: false,
          suggestions: [],
        }),
      });
    });

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await page.getByTestId('resolve-query').fill('SQA Higher maths exam day');
    await page.getByTestId('resolve-button').click();

    await expect(page.getByTestId('deadline-date')).toHaveValue('05/05/2026');
    await expect(page.getByTestId('deadline-time')).toHaveValue('09:00');
    await expect(page.getByTestId('resolved-date-display')).toContainText('Tuesday 5 May 2026, 09:00');
  });

  test('ambiguous resolver response shows suggestions and requires confirmation', async ({ page }) => {
    await page.route('**/api/resolve-event-date', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          isoUtc: null,
          display: null,
          confidence: 'low',
          notes: 'Ambiguous event name.',
          ambiguous: true,
          suggestions: [
            {
              isoUtc: '2026-06-01T08:00:00.000Z',
              display: 'Monday 1 June 2026, 09:00',
              notes: null,
            },
            {
              isoUtc: '2026-06-08T08:00:00.000Z',
              display: 'Monday 8 June 2026, 09:00',
              notes: null,
            },
          ],
        }),
      });
    });

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await page.getByTestId('resolve-query').fill('SQA exam day');
    await page.getByTestId('resolve-button').click();

    await expect(page.getByTestId('resolve-notes')).toContainText(/ambiguous/i);
    await page.getByRole('button', { name: 'Monday 1 June 2026, 09:00' }).click();

    await expect(page.getByTestId('deadline-date')).toHaveValue('01/06/2026');
    await expect(page.getByTestId('deadline-time')).toHaveValue('09:00');
  });

  test('integration resolver path runs when OPENAI_API_KEY is available', async ({ page }) => {
    test.skip(!process.env.OPENAI_API_KEY, 'OPENAI_API_KEY not set for integration resolver test');

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await page.getByTestId('resolve-query').fill('Christmas Day 2030 at noon in London');
    await page.getByTestId('resolve-button').click();

    await expect(page.getByTestId('resolved-date-display')).not.toHaveText('');
    await expect(page.getByTestId('deadline-date')).toHaveValue(/\d{2}\/\d{2}\/\d{4}/);
    await expect(page.getByTestId('deadline-time')).toHaveValue(/\d{2}:\d{2}/);
  });
});
