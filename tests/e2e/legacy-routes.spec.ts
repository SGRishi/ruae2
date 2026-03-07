import { expect, test } from '@playwright/test';

test('legacy subject routes return not found', async ({ page }) => {
  const maths = await page.goto('/maths', { waitUntil: 'domcontentloaded' });
  expect(maths?.status()).toBe(404);
  await expect(page.locator('body')).toContainText(/not found/i);

  const ruae = await page.goto('/ruae', { waitUntil: 'domcontentloaded' });
  expect(ruae?.status()).toBe(404);
  await expect(page.locator('body')).toContainText(/not found/i);

  const login = await page.goto('/login', { waitUntil: 'domcontentloaded' });
  expect(login?.status()).toBe(404);
  await expect(page.locator('body')).toContainText(/not found/i);

  const admin = await page.goto('/admin', { waitUntil: 'domcontentloaded' });
  expect(admin?.status()).toBe(404);
  await expect(page.locator('body')).toContainText(/not found/i);
});
