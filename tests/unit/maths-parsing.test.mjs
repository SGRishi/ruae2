import test from 'node:test';
import assert from 'node:assert/strict';

function tokenizeFilename(name) {
  return String(name)
    .toLowerCase()
    .replace(/\.pdf$/i, '')
    .split(/[^a-z0-9]+/g)
    .filter(Boolean);
}

function parseYearFromFilename(name) {
  const match = String(name).match(/(19|20)\d{2}/);
  if (!match) return null;
  const year = Number(match[0]);
  if (!Number.isFinite(year) || year < 1990 || year > 2100) return null;
  return year;
}

function parseTypeFromFilename(name) {
  const lower = String(name).toLowerCase();
  const tokens = new Set(tokenizeFilename(name));
  const datasheetTokens = new Set([
    'datasheet',
    'data',
    'sheet',
    'formulasheet',
    'formula',
    'relationshipsheet',
    'relationship',
    'infosheet',
    'info',
  ]);

  if (
    [...datasheetTokens].some((t) => tokens.has(t)) ||
    lower.includes('datasheet') ||
    lower.includes('data sheet') ||
    lower.includes('formula sheet') ||
    lower.includes('relationship sheet') ||
    lower.includes('info sheet')
  ) {
    return 'datasheet';
  }
  if (
    tokens.has('msch') ||
    tokens.has('mark') ||
    tokens.has('marking') ||
    tokens.has('scheme') ||
    lower.includes('msch') ||
    lower.includes('marking') ||
    lower.includes('mark')
  ) {
    return 'mark_scheme';
  }
  return 'past_paper';
}

test('filename parsing extracts year + type', () => {
  assert.equal(parseYearFromFilename('HmathsSQApp2025.pdf'), 2025);
  assert.equal(parseTypeFromFilename('HmathsSQApp2025.pdf'), 'past_paper');

  assert.equal(parseYearFromFilename('HmathsSQAmsch2019.pdf'), 2019);
  assert.equal(parseTypeFromFilename('HmathsSQAmsch2019.pdf'), 'mark_scheme');

  assert.equal(parseYearFromFilename('Higher_Maths_Datasheet_2024_Paper_1.pdf'), 2024);
  assert.equal(parseTypeFromFilename('Higher_Maths_Datasheet_2024_Paper_1.pdf'), 'datasheet');
});

test('anchor detection regex matches main anchors only', () => {
  const anchor = /^\d{1,2}\.$/;
  assert.equal(anchor.test('1.'), true);
  assert.equal(anchor.test('12.'), true);
  assert.equal(anchor.test('1'), false);
  assert.equal(anchor.test('1)'), false);
  assert.equal(anchor.test('(1.)'), false);
});
