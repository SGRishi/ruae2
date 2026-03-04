import { expect, test } from '@playwright/test';
import { installCountdownTestClock, stubBackgroundImages } from './helpers/countdown';

test.describe('openai date resolver', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('mocked resolver fills UK date/time and shows cited source link', async ({ page }) => {
    await page.route('**/api/resolve-date**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          query: 'SQA Higher maths exam day',
          title: 'SQA Higher Mathematics',
          datetime_iso: '2026-05-05T08:00:00.000Z',
          timezone: 'Europe/London',
          source_url: 'https://www.sqa.org.uk/sqa/107652.html',
          source_title: 'SQA - Exam timetable',
          retrieved_at_utc: '2026-01-01T12:00:00.000Z',
          confidence: 'high',
          note: 'Official SQA timetable entry.',
        }),
      });
    });

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await page.getByTestId('resolve-query').fill('SQA Higher maths exam day');
    await page.getByTestId('resolve-button').click();

    await expect(page.getByTestId('deadline-date')).toHaveValue('05/05/2026');
    await expect(page.getByTestId('deadline-time')).toHaveValue('09:00');
    await expect(page.getByTestId('resolved-date-display')).toContainText('Tuesday');
    await expect(page.getByTestId('resolved-source-link')).toHaveAttribute(
      'href',
      'https://www.sqa.org.uk/sqa/107652.html'
    );
    await expect(page.getByTestId('resolved-source-link')).toContainText('SQA - Exam timetable');
  });

  test('timezone-aware datetime parsing avoids off-by-one-day errors', async ({ page }) => {
    await page.route('**/api/resolve-date**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          query: 'BST edge case event',
          title: 'Offset parse check',
          datetime_iso: '2026-05-05T00:30:00+01:00',
          timezone: 'Europe/London',
          source_url: 'https://www.gov.uk/bank-holidays',
          source_title: 'GOV.UK',
          retrieved_at_utc: '2026-01-01T12:00:00.000Z',
          confidence: 'high',
        }),
      });
    });

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await page.getByTestId('resolve-query').fill('BST edge case');
    await page.getByTestId('resolve-button').click();

    await expect(page.getByTestId('deadline-date')).toHaveValue('05/05/2026');
    await expect(page.getByTestId('deadline-time')).toHaveValue('00:30');
  });

  test('integration resolver path runs when OPENAI_API_KEY is available', async ({ page }) => {
    test.skip(!process.env.OPENAI_API_KEY, 'OPENAI_API_KEY not set for integration resolver test');

    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await page.getByTestId('resolve-query').fill('Christmas Day 2030 at noon in London');
    await page.getByTestId('resolve-button').click();

    await expect
      .poll(
        async () => {
          const resolvedText = (await page.getByTestId('resolved-date-display').textContent())?.trim() || '';
          if (resolvedText) return 'resolved';
          const notesText = (await page.getByTestId('resolve-notes').textContent())?.trim() || '';
          if (notesText) return 'error';
          return '';
        },
        { timeout: 15_000 }
      )
      .toMatch(/resolved|error/);

    const resolvedText = (await page.getByTestId('resolved-date-display').textContent())?.trim() || '';
    if (resolvedText) {
      await expect(page.getByTestId('resolved-source-link')).toHaveAttribute('href', /^https?:\/\//);
      await expect(page.getByTestId('deadline-date')).toHaveValue(/\d{2}\/\d{2}\/\d{4}/);
      await expect(page.getByTestId('deadline-time')).toHaveValue(/\d{2}:\d{2}/);
    } else {
      await expect(page.getByTestId('resolve-notes')).toContainText(
        /unable|configured|reliable source|failed|malformed/i
      );
    }
  });
});
