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

test('root page does not expose legacy subject or auth website routes', async () => {
  assert.doesNotMatch(rootPage, /href="\/ruae\b/i);
  assert.doesNotMatch(rootPage, /href="\/maths\b/i);
  assert.doesNotMatch(rootPage, /href="\/login\b/i);
  assert.doesNotMatch(rootPage, /href="\/admin\b/i);
  assert.doesNotMatch(rootPage, /RUAE|English|Maths/i);
});

test('root page mirrors /countdown UI markup', async () => {
  assert.equal(rootPage, countdownPage);
});
