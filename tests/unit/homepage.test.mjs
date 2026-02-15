import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const homepage = await readFile(new URL('../../public/index.html', import.meta.url), 'utf8');

test('homepage uses the new layout and keeps the key navigation links', async () => {
  assert.match(homepage, /<header\s+class="nav"/i);
  assert.match(homepage, /<section\s+class="hero"/i);
  assert.match(homepage, /<section\s+class="grid"/i);
  assert.match(homepage, /href="\/home\.css\b/i);

  // Core routes must remain reachable from the homepage.
  assert.match(homepage, /href="\/login\//i);
  assert.match(homepage, /href="\/ruae\b/i);
  assert.match(homepage, /href="\/maths\b/i);
});

test('homepage buttons are real links (no missing href)', async () => {
  const btnTags = Array.from(homepage.matchAll(/<a\b[^>]*\bclass="[^"]*\bbtn\b[^"]*"[^>]*>/gi)).map(
    (m) => m[0]
  );
  assert.ok(btnTags.length >= 3, 'expected at least 3 .btn links on the homepage');

  for (const tag of btnTags) {
    assert.match(tag, /\bhref="[^"]+"/i);
    assert.doesNotMatch(tag, /\bhref="#"/i);
  }
});

test('homepage referenced static assets exist in public/', async () => {
  const css = await readFile(new URL('../../public/home.css', import.meta.url), 'utf8');
  assert.ok(css.length > 200, 'home.css should not be empty');

  const heroImage = await readFile(new URL('../../public/media/hero-study.jpg', import.meta.url));
  assert.ok(heroImage.byteLength > 50_000, 'hero image should be present and non-trivial');
});
