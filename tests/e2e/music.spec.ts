import { expect, test } from '@playwright/test';
import { installCountdownTestClock, stubBackgroundImages } from './helpers/countdown';

test.describe('ambient music', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page);
    await stubBackgroundImages(page);
  });

  test('uses ClassicFM stream and handles play result visibly', async ({ page }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });

    await expect(page.getByTestId('audio-element')).toHaveAttribute(
      'src',
      'https://ice-the.musicradio.com/ClassicFMMP3'
    );
    await expect(page.getByTestId('volume-slider')).toBeVisible();

    const initiallyPaused = await page.getByTestId('audio-element').evaluate((el) => el.paused);
    expect(initiallyPaused).toBe(true);

    await page.getByTestId('volume-slider').fill('0.25');
    await expect
      .poll(() =>
        page.getByTestId('audio-element').evaluate((el) => Number((el as HTMLAudioElement).volume.toFixed(2)))
      )
      .toBe(0.25);

    await page.getByTestId('music-play').click();

    await expect
      .poll(async () => {
        const paused = await page.getByTestId('audio-element').evaluate((el) => el.paused);
        const status = String((await page.getByTestId('audio-status').textContent()) || '').toLowerCase();
        const errorVisible = await page.getByTestId('music-error').isVisible();
        return paused === false || errorVisible || status.includes('playing') || status.includes('paused');
      })
      .toBe(true);

    await page.getByTestId('music-pause').click();
    await expect
      .poll(() => page.getByTestId('audio-element').evaluate((el) => el.paused))
      .toBe(true);
  });
});
