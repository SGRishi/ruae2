import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createApiHandler,
  createMemoryStore,
  createMemoryCountdownStore,
  __test,
} from '../../worker.js';

function getSetCookies(response) {
  if (typeof response.headers.getSetCookie === 'function') {
    return response.headers.getSetCookie();
  }
  const single = response.headers.get('set-cookie');
  return single ? [single] : [];
}

function applySetCookies(cookieJar, setCookieHeaders) {
  for (const header of setCookieHeaders) {
    const parsed = __test.parseSetCookieValue(header);
    if (!parsed) continue;

    if (/max-age=0/i.test(header)) {
      cookieJar.delete(parsed.name);
      continue;
    }

    cookieJar.set(parsed.name, parsed.value);
  }
}

function cookieHeader(cookieJar) {
  return Array.from(cookieJar.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');
}

async function apiCall(handler, env, path, options = {}, cookieJar = new Map()) {
  const method = options.method || 'GET';
  const headers = new Headers(options.headers || {});
  headers.set('Origin', options.origin || 'https://rishisubjects.co.uk');

  const cookie = cookieHeader(cookieJar);
  if (cookie) {
    headers.set('Cookie', cookie);
  }

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
  applySetCookies(cookieJar, getSetCookies(response));

  let data = {};
  try {
    data = await response.clone().json();
  } catch {
    data = {};
  }

  return { response, data };
}

function buildCountdownEnv() {
  return {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };
}

test('countdown API: public timers are readable without auth and expose start/end timestamps', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });
  const env = buildCountdownEnv();

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      deadlineMs: fixedNow + 10 * 60_000,
      isPublic: true,
    },
  });

  assert.equal(created.response.status, 200);
  assert.equal(created.data.ok, true);
  assert.equal(created.data.timer.isPublic, true);
  assert.equal(created.data.timer.startAtMs, fixedNow);
  assert.equal(created.data.timer.endAtMs, fixedNow + 10 * 60_000);
  assert.equal(created.data.timer.deadlineMs, created.data.timer.endAtMs);

  const timerId = created.data.timer.id;

  const publicRead = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}`
  );
  assert.equal(publicRead.response.status, 200);
  assert.equal(publicRead.data.timer.id, timerId);
  assert.equal(publicRead.data.timer.canEdit, false);

  const ownerRead = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}&token=${encodeURIComponent(created.data.ownerToken)}`
  );
  assert.equal(ownerRead.response.status, 200);
  assert.equal(ownerRead.data.timer.canEdit, true);
});

test('countdown API: durationMinutes creates server-timed deadlines', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });
  const env = buildCountdownEnv();

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      durationMinutes: 10,
      isPublic: true,
    },
  });

  assert.equal(created.response.status, 200);
  assert.equal(created.data.serverNowMs, fixedNow);
  assert.equal(created.data.timer.startAtMs, fixedNow);
  assert.equal(created.data.timer.endAtMs, fixedNow + 10 * 60_000);
});

test('countdown API: private timers require password and can be unlocked via access endpoint', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });
  const env = buildCountdownEnv();
  const cookieJar = new Map();

  const created = await apiCall(
    handler,
    env,
    '/api/countdown/timer',
    {
      method: 'POST',
      json: {
        deadlineMs: fixedNow + 20 * 60_000,
        isPublic: false,
        password: 'StrongPassword123',
      },
    },
    cookieJar
  );

  assert.equal(created.response.status, 200);
  const timerId = created.data.timer.id;

  const denied = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}`,
    {},
    cookieJar
  );
  assert.equal(denied.response.status, 403);
  assert.equal(denied.data.requiresPassword, true);

  const wrongPassword = await apiCall(
    handler,
    env,
    '/api/countdown/access',
    {
      method: 'POST',
      json: {
        id: timerId,
        password: 'WrongPassword123',
      },
    },
    cookieJar
  );
  assert.equal(wrongPassword.response.status, 401);

  const access = await apiCall(
    handler,
    env,
    '/api/countdown/access',
    {
      method: 'POST',
      json: {
        id: timerId,
        password: 'StrongPassword123',
      },
    },
    cookieJar
  );
  assert.equal(access.response.status, 200);
  assert.equal(access.data.ok, true);

  const unlocked = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}`,
    {},
    cookieJar
  );
  assert.equal(unlocked.response.status, 200);
  assert.equal(unlocked.data.timer.canEdit, false);

  const ownerRead = await apiCall(
    handler,
    env,
    `/api/countdown/timer?id=${encodeURIComponent(timerId)}&token=${encodeURIComponent(created.data.ownerToken)}`,
    {},
    cookieJar
  );
  assert.equal(ownerRead.response.status, 200);
  assert.equal(ownerRead.data.timer.canEdit, true);
});

test('countdown API: owner can toggle public/private and private requires password when re-enabled', async () => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });
  const env = buildCountdownEnv();

  const created = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'POST',
    json: {
      deadlineMs: fixedNow + 20 * 60_000,
      isPublic: false,
      password: 'StrongPassword123',
    },
  });

  const timerId = created.data.timer.id;
  const ownerToken = created.data.ownerToken;

  const toPublic = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'PATCH',
    json: {
      id: timerId,
      token: ownerToken,
      isPublic: true,
    },
  });
  assert.equal(toPublic.response.status, 200);
  assert.equal(toPublic.data.timer.isPublic, true);

  const failPrivateWithoutPassword = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'PATCH',
    json: {
      id: timerId,
      token: ownerToken,
      isPublic: false,
    },
  });
  assert.equal(failPrivateWithoutPassword.response.status, 400);

  const backToPrivate = await apiCall(handler, env, '/api/countdown/timer', {
    method: 'PATCH',
    json: {
      id: timerId,
      token: ownerToken,
      isPublic: false,
      password: 'StrongPassword123',
    },
  });
  assert.equal(backToPrivate.response.status, 200);
  assert.equal(backToPrivate.data.timer.isPublic, false);
});

test('countdown API: expired flag becomes true when now passes deadline', async () => {
  let nowMs = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => nowMs });
  const env = buildCountdownEnv();

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
