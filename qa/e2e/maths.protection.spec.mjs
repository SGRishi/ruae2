import { test, expect } from '@playwright/test';

test('maths is protected by login', async ({ page }) => {
  await page.goto('/maths', { waitUntil: 'domcontentloaded' });

  await expect(page).toHaveURL(/\/login\/\?next=/);
  await expect(page.getByRole('heading', { name: /RUAE Access/i })).toBeVisible();
});

