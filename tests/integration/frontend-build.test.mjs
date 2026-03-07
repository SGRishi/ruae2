import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..');

function runBuild() {
  const result = spawnSync(process.execPath, ['scripts/build-frontend.mjs'], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      // Keep the build deterministic and same-origin for tests.
      API_BASE: '',
    },
  });
  assert.equal(result.status, 0, 'frontend build should succeed');
}

async function assertMissing(relativePath) {
  const fullPath = path.join(repoRoot, 'dist', relativePath);
  await assert.rejects(
    stat(fullPath),
    (error) => error && error.code === 'ENOENT',
    `expected ${relativePath} to be removed from dist/`
  );
}

test('frontend build outputs countdown-only site and cleans removed pages', async () => {
  await mkdir(path.join(repoRoot, 'dist'), { recursive: true });
  const stalePath = path.join(repoRoot, 'dist', 'stale-legacy-file.txt');
  await writeFile(stalePath, 'stale', 'utf8');

  runBuild();

  await assertMissing('stale-legacy-file.txt');

  const distIndex = await readFile(path.join(repoRoot, 'dist', 'index.html'), 'utf8');
  assert.match(distIndex, /data-testid="countdown-main"/i);
  assert.match(distIndex, /src="\/countdown\/countdown\.js\?v=/i);

  const distCountdownCss = await readFile(
    path.join(repoRoot, 'dist', 'countdown', 'countdown.css'),
    'utf8'
  );
  assert.ok(distCountdownCss.length > 200, 'dist/countdown/countdown.css should exist');

  await assertMissing('home.css');
  await assertMissing('home.js');
  await assertMissing('app.js');
  await assertMissing('styles.css');
  await assertMissing('media/hero-study.jpg');
  await assertMissing('media/winter-panorama-bled.jpg');
});
