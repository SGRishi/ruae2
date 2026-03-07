import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const rootPage = await readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
const countdownPage = await readFile(
  new URL('../../public/countdown/index.html', import.meta.url),
  'utf8'
);

test('root page is the countdown app', async () => {
  assert.match(rootPage, /data-testid="countdown-main"/i);
  assert.match(rootPage, /data-testid="countdown-display"/i);
  assert.match(rootPage, /data-testid="timer-form"/i);
  assert.match(rootPage, /src="\/countdown\/countdown\.js\?v=/i);
  assert.match(rootPage, /href="\/countdown\/countdown\.css\?v=/i);
});

test('root page does not expose legacy navigation links', async () => {
  assert.doesNotMatch(rootPage, /href="\/legacy\b/i);
  assert.doesNotMatch(rootPage, /href="\/old-route\b/i);
});

test('root page mirrors /countdown UI markup', async () => {
  assert.equal(rootPage, countdownPage);
});
