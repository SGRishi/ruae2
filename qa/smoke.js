import assert from 'node:assert/strict';
import { createApiHandler } from '../worker.js';
import { createQaEnv, QA_SESSIONS, qaBaseUrl } from './fixtures/maths-env.mjs';

const ORIGIN = qaBaseUrl(process.env.PORT || 8789);
const { env } = await createQaEnv(ORIGIN);
const handler = createApiHandler();

async function apiJson(path, token) {
  const headers = new Headers();
  headers.set('Origin', ORIGIN);
  headers.set('Cookie', `ruae_session=${token}`);
  const request = new Request(`${ORIGIN}${path}`, { method: 'GET', headers });
  const response = await handler.fetch(request, env);
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

async function apiBytes(path, token) {
  const headers = new Headers();
  headers.set('Origin', ORIGIN);
  headers.set('Cookie', `ruae_session=${token}`);
  const request = new Request(`${ORIGIN}${path}`, { method: 'GET', headers });
  const response = await handler.fetch(request, env);
  const bytes = new Uint8Array(await response.arrayBuffer());
  return { response, bytes };
}

const token = QA_SESSIONS.approved.token;

const years = await apiJson('/api/maths/years', token);
assert.equal(years.response.status, 200);
assert.ok(Array.isArray(years.data.years));
assert.ok(years.data.years.includes(2023));

const list = await apiJson('/api/maths/questions?year=2023&paper=2', token);
assert.equal(list.response.status, 200);
assert.ok(Array.isArray(list.data.questions));
assert.ok(list.data.questions.some((q) => q.id === 'q_2023_2_2'));

const detail = await apiJson('/api/maths/question?id=q_2023_2_2', token);
assert.equal(detail.response.status, 200);
assert.equal(detail.data.question.id, 'q_2023_2_2');
assert.equal(Array.isArray(detail.data.question.questionCrops), true);
assert.equal(detail.data.question.questionCrops.length, 2);
assert.equal(Array.isArray(detail.data.question.answerCrops), true);
assert.equal(detail.data.question.answerCrops.length, 2);

const cropId = detail.data.question.questionCrops[0].id;
const crop = await apiBytes(`/api/maths/crops/${encodeURIComponent(cropId)}.png`, token);
assert.equal(crop.response.status, 200);
assert.ok(String(crop.response.headers.get('content-type') || '').includes('image/png'));
assert.ok(crop.bytes.byteLength > 0);

process.stdout.write('Smoke OK\n');
