import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiHandler, createMemoryStore, createMemoryCountdownStore } from '../../worker.js';

async function apiCall(handler, env, path, options = {}) {
  const method = options.method || 'GET';
  const headers = new Headers(options.headers || {});
  headers.set('Origin', options.origin || 'https://rishisubjects.co.uk');

  let body;
  if (options.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(options.json);
  }

  const request = new Request(`https://api.rishisubjects.co.uk${path}`, {
    method,
    headers,
    body,
  });

  const response = await handler.fetch(request, env);

  let data = {};
  try {
    data = await response.clone().json();
  } catch {
    data = {};
  }

  return { response, data };
}

test('countdown API: public timers are readable without auth and preserve countdown data', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      deadlineMs: fixedNow + 10 * 60_000,
      isPublic: true,
    },
  });

  assert.equal(created.response.status, 200);
  assert.equal(created.data.ok, true);
  assert.equal(Number.isFinite(Number(created.data.serverNowMs)), true);
  assert.equal(created.data.timer.isPublic, true);
  assert.equal(typeof created.data.timer.id, 'string');
  assert.equal(typeof created.data.ownerToken, 'string');

  const timerId = created.data.timer.id;

  const publicRead = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}`
  );
  assert.equal(publicRead.response.status, 200);
  assert.equal(publicRead.data.ok, true);
  assert.equal(Number.isFinite(Number(publicRead.data.serverNowMs)), true);
  assert.equal(publicRead.data.timer.id, timerId);
  assert.equal(publicRead.data.timer.canEdit, false);

  const ownerRead = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}&token=${encodeURIComponent(created.data.ownerToken)}`
  );
  assert.equal(ownerRead.response.status, 200);
  assert.equal(Number.isFinite(Number(ownerRead.data.serverNowMs)), true);
  assert.equal(ownerRead.data.timer.canEdit, true);
  assert.equal(ownerRead.data.timer.deadlineMs, created.data.timer.deadlineMs);
});

test('countdown API: durationMinutes creates server-timed deadlines', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      durationMinutes: 10,
      isPublic: true,
    },
  });

  assert.equal(created.response.status, 200);
  assert.equal(created.data.ok, true);
  assert.equal(created.data.serverNowMs, fixedNow);
  assert.equal(created.data.timer.deadlineMs, fixedNow + 10 * 60_000);
});

test('countdown API: private timers require exact token and can be toggled public', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      deadlineMs: fixedNow + 20 * 60_000,
      isPublic: false,
    },
  });

  const timerId = created.data.timer.id;
  const ownerToken = created.data.ownerToken;

  const denied = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}`
  );
  assert.equal(denied.response.status, 403);
  assert.equal(
    String(denied.data.error || '')
      .toLowerCase()
      .includes('private'),
    true
  );

  const ownerRead = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}&token=${encodeURIComponent(ownerToken)}`
  );
  assert.equal(ownerRead.response.status, 200);
  assert.equal(ownerRead.data.timer.canEdit, true);

  const toggled = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'PATCH',
    json: {
      id: timerId,
      token: ownerToken,
      isPublic: true,
    },
  });
  assert.equal(toggled.response.status, 200);
  assert.equal(Number.isFinite(Number(toggled.data.serverNowMs)), true);
  assert.equal(toggled.data.timer.isPublic, true);

  const nowPublic = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}`
  );
  assert.equal(nowPublic.response.status, 200);
  assert.equal(nowPublic.data.timer.isPublic, true);
});

test('countdown API: expired flag becomes true when now passes the deadline', async () => {
  let nowMs = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => nowMs });

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      deadlineMs: nowMs + 5_000,
      isPublic: true,
    },
  });

  const timerId = created.data.timer.id;
  const ownerToken = created.data.ownerToken;

  nowMs += 30_000;

  const read = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}&token=${encodeURIComponent(ownerToken)}`
  );

  assert.equal(read.response.status, 200);
  assert.equal(read.data.expired, true);
});
