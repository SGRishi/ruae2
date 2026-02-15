import { test, expect } from '@playwright/test';
import { QA_SESSIONS } from '../fixtures/maths-env.mjs';
import { setSessionCookie } from './helpers/session.mjs';

test('approved user can access /maths, filter, URL sync, and keyboard shortcuts', async ({ page, context }) => {
  await setSessionCookie(context, QA_SESSIONS.approved.token);

  const yearsRes = await page.request.get('/api/maths/years');
  await expect(yearsRes).toBeOK();

  await page.goto('/maths', { waitUntil: 'domcontentloaded' });
  await expect(page.getByTestId('maths-list-view')).toBeVisible();

  await page.getByTestId('maths-year-select').selectOption('2023');
  await page.getByTestId('maths-paper-select').selectOption('2');
  await expect(page).toHaveURL(/\/maths\?year=2023&paper=2/);

  const cards = page.getByTestId('maths-question-cards').locator('[data-testid^="maths-question-card-"]');
  await expect(cards).toHaveCount(2);
  await expect(page.getByTestId('maths-question-card-q_2024_1_1')).toHaveCount(0);

  await page.getByTestId('maths-question-card-q_2023_2_1').click();
  await expect(page).toHaveURL(/\/maths\/q\//);

  // "/" focuses search.
  await page.keyboard.press('/');
  await expect(page.getByTestId('maths-search-input')).toBeFocused();

  // Leave typing target so shortcuts work.
  await page.locator('body').click();

  // A toggles answer.
  await expect(page.getByTestId('maths-answer-crops')).toBeHidden();
  await page.keyboard.press('A');
  await expect(page.getByTestId('maths-answer-crops')).toBeVisible();

  // D toggles datasheet modal.
  await page.keyboard.press('D');
  await expect(page.getByTestId('maths-datasheet-modal')).toBeVisible();
  await expect(page.getByTestId('maths-datasheet-empty')).toContainText(/no datasheet/i);
  await page.keyboard.press('Escape');
  await expect(page.getByTestId('maths-modal-root')).toBeEmpty();

  // Left/Right navigates between questions.
  await page.keyboard.press('ArrowRight');
  await expect(page).toHaveURL(/q_2023_2_2/);
  await page.keyboard.press('ArrowLeft');
  await expect(page).toHaveURL(/q_2023_2_1/);

  // R toggles review mode.
  await page.keyboard.press('R');
  await expect(page).toHaveURL(/\/maths\/review\//);
  await expect(page.getByTestId('maths-review-view')).toBeVisible();
  await page.keyboard.press('R');
  await expect(page).toHaveURL(/\/maths\/q\//);
});

