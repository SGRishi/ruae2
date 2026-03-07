import { expect, test } from '@playwright/test';

test('live smoke: countdown page loads in read-only mode', async ({ page }) => {
  const smokePath = process.env.SMOKE_PATH || '/';

  await page.goto(smokePath, { waitUntil: 'domcontentloaded' });
  const embedHeadersResponse = await page.request.get('/countdown/?embed=1');
  expect(embedHeadersResponse.ok()).toBe(true);
  const embedHeaders = embedHeadersResponse.headers();
  const xFrameOptions = String(embedHeaders['x-frame-options'] || '').toLowerCase();
  expect(xFrameOptions).not.toContain('sameorigin');
  expect(xFrameOptions).not.toContain('deny');
  const csp = String(embedHeaders['content-security-policy'] || '').toLowerCase();
  if (csp.includes('frame-ancestors')) {
    expect(csp).toContain('frame-ancestors *');
  }

  const hasNewUi = (await page.getByTestId('countdown-display').count()) > 0;

  if (hasNewUi) {
    await expect(page.getByTestId('bg-image')).toBeVisible();
    await expect(page.getByTestId('countdown-display')).toBeVisible();
    await expect(page.getByTestId('settings-menu-toggle')).toBeVisible();
    await expect(page.getByTestId('label-days')).toHaveText(/days/i);
    await expect(page.getByTestId('audio-element')).toHaveAttribute(
      'src',
      'https://ice-the.musicradio.com/ClassicFMMP3'
    );
    return;
  }

  // Backward-compatible live smoke for the existing production countdown UI.
  await expect(page.getByRole('heading', { name: /countdown/i })).toBeVisible();
  await expect(page.locator('[role=\"timer\"], timer')).toBeVisible();
  await expect(page.getByRole('button', { name: /play ambience|play ambient/i })).toBeVisible();
});
