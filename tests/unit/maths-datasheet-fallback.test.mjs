import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';

const mathsSource = await readFile(new URL('../../public/maths/maths.js', import.meta.url), 'utf8');

test('maths datasheet shortcut falls back to the shipped formula list PDF', async () => {
  assert.match(
    mathsSource,
    /const\s+STATIC_DATASHEET_PATH\s*=\s*['"]\/Higher-Maths-Exam-Formulae-List\.pdf['"]\s*;/i
  );
  assert.match(mathsSource, /toSameOriginUrl\(STATIC_DATASHEET_PATH\)/);
  assert.match(
    mathsSource,
    /if\s*\(\s*event\.key\s*===\s*['"]d['"]\s*\|\|\s*event\.key\s*===\s*['"]D['"]\s*\)/
  );
});

test('root formula list PDF exists and is non-trivial', async () => {
  const pdfStat = await stat(new URL('../../Higher-Maths-Exam-Formulae-List.pdf', import.meta.url));
  assert.ok(pdfStat.size > 50_000, 'Higher-Maths-Exam-Formulae-List.pdf should exist in repo root');
});
