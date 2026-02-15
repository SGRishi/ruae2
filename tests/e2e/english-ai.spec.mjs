import { test, expect } from '@playwright/test';

test('R-AI-01: approved user can check English AI marking without login redirect', async ({ page, context }) => {
  await context.setExtraHTTPHeaders({ 'x-test-auth': 'approved' });

  await page.goto('/ruae/', { waitUntil: 'domcontentloaded' });
  await expect(page).not.toHaveURL(/\/(login|auth)\b/i);

  await expect(page.locator('#aiMode')).toBeVisible();
  await page.locator('#aiMode').selectOption('mark');

  const question = page.locator('section.question').first();
  await expect(question).toBeVisible();

  await question
    .locator('textarea')
    .fill('The passage presents Central Valley as productive and fertile with extensive orchards and farming.');

  const matchResPromise = page.waitForResponse((res) => {
    return res.url().includes('/api/match') && res.request().method() === 'POST';
  });

  await question.getByRole('button', { name: /^check answer$/i }).click();

  const matchRes = await matchResPromise;

  await expect(page).not.toHaveURL(/\/(login|auth)\b/i);

  expect(matchRes.url()).toContain('/api/match');
  expect(matchRes.request().redirectedFrom()).toBeNull();
  expect([401, 403]).not.toContain(matchRes.status());

  const payload = await matchRes.json();
  expect(payload.ok).toBe(true);
  expect(typeof payload.reasoning).toBe('string');
  expect(payload.reasoning.length).toBeGreaterThan(0);

  const aiResult = question.locator('.ai-result');
  await expect(aiResult).toBeVisible();
  await expect(aiResult).toContainText(/Score:\s*\d+\s*\/\s*\d+/);
  await expect(aiResult).toContainText(/QA stub feedback/i);
});

