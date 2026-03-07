import assert from 'node:assert/strict';
import { createApiHandler } from '../worker.js';
import { createCountdownQaEnv, qaBaseUrl } from './fixtures/countdown-env.mjs';

const ORIGIN = qaBaseUrl(process.env.PORT || 8789);
const { env } = createCountdownQaEnv(ORIGIN);
const handler = createApiHandler();

async function apiJson(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Origin', ORIGIN);

  let body;
  if (options.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(options.json);
  }

  const request = new Request(`${ORIGIN}${path}`, {
    method: options.method || 'GET',
    headers,
    body,
  });

  const response = await handler.fetch(request, env);
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

const time = await apiJson('/api/time');
assert.equal(time.response.status, 200);
assert.equal(typeof time.data.nowMs, 'number');

const health = await apiJson('/api/health');
assert.equal(health.response.status, 200);
assert.equal(health.data.service, 'countdown-api');

const deadlineMs = Date.now() + 60 * 60 * 1000;
const created = await apiJson('/api/countdown/timer', {
  method: 'POST',
  json: {
    title: 'QA Countdown Smoke',
    deadlineMs,
    isPublic: true,
    units: ['hours', 'minutes', 'seconds'],
  },
});

assert.equal(created.response.status, 200);
assert.equal(created.data.ok, true);
assert.equal(typeof created.data.ownerToken, 'string');
assert.equal(typeof created.data.timer?.id, 'string');
assert.equal(created.data.timer?.isPublic, true);

const timerId = created.data.timer.id;
const ownerToken = created.data.ownerToken;

const publicRead = await apiJson(`/api/countdown/timer?id=${encodeURIComponent(timerId)}`);
assert.equal(publicRead.response.status, 200);
assert.equal(publicRead.data.ok, true);
assert.equal(publicRead.data.timer?.id, timerId);
assert.equal(publicRead.data.timer?.canEdit, false);

const ownerRead = await apiJson(
  `/api/countdown/timer?id=${encodeURIComponent(timerId)}&token=${encodeURIComponent(ownerToken)}`
);
assert.equal(ownerRead.response.status, 200);
assert.equal(ownerRead.data.ok, true);
assert.equal(ownerRead.data.timer?.canEdit, true);

process.stdout.write('Smoke OK\n');
