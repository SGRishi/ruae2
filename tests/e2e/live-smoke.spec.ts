import { expect, test } from '@playwright/test';

test('live smoke: countdown page loads in read-only mode', async ({ page }) => {
  const smokePath = process.env.SMOKE_PATH || '/countdown';

  await page.goto(smokePath, { waitUntil: 'domcontentloaded' });

  await expect(page.getByTestId('bg-image')).toBeVisible();
  await expect(page.getByTestId('countdown-display')).toBeVisible();
  await expect(page.getByTestId('label-days')).toHaveText(/days/i);
  await expect(page.getByTestId('audio-element')).toHaveAttribute(
    'src',
    'https://ice-the.musicradio.com/ClassicFMMP3'
  );
});
