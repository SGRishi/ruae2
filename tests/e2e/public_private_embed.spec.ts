import { BrowserContext, expect, test } from '@playwright/test';
import {
  createCountdown,
  installCountdownTestClock,
  stubBackgroundImages,
  toPathnameAndSearch,
  totalSeconds,
} from './helpers/countdown';

const TEST_NOW = Date.UTC(2026, 0, 1, 12, 0, 0);

async function openIsolated(browserContextFactory: () => Promise<BrowserContext>, path: string) {
  const context = await browserContextFactory();
  const page = await context.newPage();
  await installCountdownTestClock(page, { nowMs: TEST_NOW });
  await stubBackgroundImages(page);
  await page.goto(path, { waitUntil: 'domcontentloaded' });
  return { context, page };
}

test.describe('public/private/embed urls', () => {
  test.beforeEach(async ({ page }) => {
    await installCountdownTestClock(page, { nowMs: TEST_NOW });
    await stubBackgroundImages(page);
  });

  test('public works, private is password gated, and embed is iframe-friendly', async ({
    page,
    browser,
  }) => {
    await page.goto('/countdown', { waitUntil: 'domcontentloaded' });
    const nowMs = Date.now();

    await createCountdown(page, {
      title: 'Public timer',
      endAtMs: nowMs + 6 * 60 * 60 * 1000,
      mode: 'public',
    });

    await expect(page.getByTestId('public-url')).toHaveValue(/\/countdown\//);
    await expect(page.getByTestId('embed-url')).toHaveValue(/embed=1/);
    const publicUrl = await page.getByTestId('public-url').inputValue();
    const embedUrl = await page.getByTestId('embed-url').inputValue();

    const mkContext = () => browser.newContext();

    const viewerA = await openIsolated(mkContext, toPathnameAndSearch(publicUrl));
    await expect(viewerA.page.getByTestId('countdown-display')).toBeVisible();

    const viewerB = await openIsolated(mkContext, toPathnameAndSearch(publicUrl));
    await expect(viewerB.page.getByTestId('countdown-display')).toBeVisible();

    const [secondsA, secondsB] = await Promise.all([
      totalSeconds(viewerA.page),
      totalSeconds(viewerB.page),
    ]);
    // CI runners can introduce a few seconds of spread between fresh isolated contexts.
    expect(Math.abs(secondsA - secondsB)).toBeLessThanOrEqual(5);

    const embedViewer = await openIsolated(mkContext, toPathnameAndSearch(embedUrl));
    await expect(embedViewer.page.getByTestId('countdown-display')).toBeVisible();
    await expect(embedViewer.page.getByTestId('timer-form')).toBeHidden();

    const iframeHost = await openIsolated(mkContext, '/countdown');
    await iframeHost.page.setContent(
      `<iframe data-testid="embed-frame" src="${toPathnameAndSearch(
        embedUrl
      )}" style="width:100%;height:600px;border:0"></iframe>`
    );
    await expect(
      iframeHost.page.frameLocator('[data-testid="embed-frame"]').getByTestId('countdown-display')
    ).toBeVisible();

    const privatePassword = 'StrongPassword123';
    const privateCreator = await openIsolated(mkContext, '/countdown');
    const privateNow = Date.now();
    await createCountdown(privateCreator.page, {
      title: 'Private timer',
      endAtMs: privateNow + 8 * 60 * 60 * 1000,
      mode: 'private',
      password: privatePassword,
    });

    await expect(privateCreator.page.getByTestId('private-url')).toHaveValue(/\/countdown\//);
    const privateUrl = await privateCreator.page.getByTestId('private-url').inputValue();
    const privateViewer = await openIsolated(mkContext, toPathnameAndSearch(privateUrl));

    await expect(privateViewer.page.getByTestId('password-input')).toBeVisible();
    await privateViewer.page.getByTestId('password-input').fill('WrongPassword123');
    await privateViewer.page.getByTestId('password-submit').click();
    await expect(privateViewer.page.getByTestId('password-message')).toContainText(
      /incorrect|access denied/i
    );

    await privateViewer.page.getByTestId('password-input').fill(privatePassword);
    await privateViewer.page.getByTestId('password-submit').click();
    await expect(privateViewer.page.getByTestId('password-gate')).toBeHidden();
    await expect(privateViewer.page.getByTestId('countdown-display')).toBeVisible();

    await Promise.all([
      viewerA.context.close(),
      viewerB.context.close(),
      embedViewer.context.close(),
      iframeHost.context.close(),
      privateCreator.context.close(),
      privateViewer.context.close(),
    ]);
  });
});
