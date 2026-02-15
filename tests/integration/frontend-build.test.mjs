import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
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

test('frontend build output includes new homepage layout and the root datasheet PDF', async () => {
  // The CI pipeline runs `npm run build` in a separate step, but we validate the
  // build output here so `npm test` catches missing assets immediately.
  runBuild();

  const distIndex = await readFile(path.join(repoRoot, 'dist', 'index.html'), 'utf8');
  assert.match(distIndex, /<header\s+class="nav"/i);
  assert.match(distIndex, /<section\s+class="hero"/i);
  assert.match(distIndex, /href="\/home\.css\b/i);

  const distCss = await readFile(path.join(repoRoot, 'dist', 'home.css'), 'utf8');
  assert.ok(distCss.length > 200, 'dist/home.css should exist');

  const distHero = await stat(path.join(repoRoot, 'dist', 'media', 'hero-study.jpg'));
  assert.ok(distHero.size > 50_000, 'dist hero image should exist');

  const distPdf = await stat(path.join(repoRoot, 'dist', 'Higher-Maths-Exam-Formulae-List.pdf'));
  assert.ok(distPdf.size > 50_000, 'dist datasheet PDF should exist');
});
