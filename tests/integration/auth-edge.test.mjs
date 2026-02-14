import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiHandler, createMemoryStore, __test } from '../../worker.js';

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

async function apiCall(handler, env, cookieJar, path, options = {}) {
  const method = options.method || 'GET';
  const headers = new Headers(options.headers || {});

  if (options.origin !== null) {
    headers.set('Origin', options.origin || 'https://rishisubjects.co.uk');
  }

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

async function bootstrapCsrf(handler, env, jar) {
  const me = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me.response.status, 200);
  assert.equal(typeof me.data.csrfToken, 'string');
  return me.data.csrfToken;
}

test('register validation rejects invalid username and weak password', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };
  const jar = new Map();
  const csrfToken = await bootstrapCsrf(handler, env, jar);

  const badUsername = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: '12', password: 'StrongPassword123' },
  });
  assert.equal(badUsername.response.status, 400);
  assert.equal(badUsername.data.ok, false);

  const weakPassword = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'student', password: 'weakpass' },
  });
  assert.equal(weakPassword.response.status, 400);
  assert.equal(weakPassword.data.ok, false);
});

test('login lockout engages after repeated failed attempts', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };
  const jar = new Map();
  const csrfToken = await bootstrapCsrf(handler, env, jar);

  const register = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      username: 'lockoutuser',
      password: 'StrongPassword123',
    },
  });
  assert.equal(register.response.status, 201);

  for (let i = 0; i < 5; i += 1) {
    const failed = await apiCall(handler, env, jar, '/api/auth/login', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
      json: {
        username: 'lockoutuser',
        password: 'WrongPassword123',
      },
    });
    assert.equal(failed.response.status, 401);
  }

  const locked = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      username: 'lockoutuser',
      password: 'WrongPassword123',
    },
  });
  assert.equal(locked.response.status, 429);
  assert.equal(locked.data.ok, false);
  assert.equal(Number(locked.response.headers.get('retry-after')) > 0, true);
});

test('match endpoint requires authentication', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };
  const jar = new Map();
  const csrfToken = await bootstrapCsrf(handler, env, jar);

  const result = await apiCall(handler, env, jar, '/api/match', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      paperId: 'H_English_2025_Ruae',
      questionNumber: 1,
      answer: 'test answer',
      mode: 'quote',
    },
  });

  assert.equal(result.response.status, 401);
  assert.equal(result.data.ok, false);
});

test('match endpoint enforces answer size and rate limits', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };
  const jar = new Map();
  let csrfToken = await bootstrapCsrf(handler, env, jar);

  const register = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      username: 'matchlimituser',
      password: 'StrongPassword123',
    },
  });
  assert.equal(register.response.status, 201);

  const login = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      username: 'matchlimituser',
      password: 'StrongPassword123',
    },
  });
  assert.equal(login.response.status, 200);
  csrfToken = login.data.csrfToken;

  const oversize = await apiCall(handler, env, jar, '/api/match', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      paperId: 'H_English_2025_Ruae',
      questionNumber: 1,
      answer: 'x'.repeat(6001),
      mode: 'quote',
    },
  });
  assert.equal(oversize.response.status, 400);

  for (let i = 0; i < 39; i += 1) {
    const limited = await apiCall(handler, env, jar, '/api/match', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
      json: {
        paperId: 'H_English_2025_Ruae',
        questionNumber: 1,
        answer: 'short answer',
        mode: 'quote',
      },
    });
    assert.equal(limited.response.status, 503);
  }

  const blocked = await apiCall(handler, env, jar, '/api/match', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      paperId: 'H_English_2025_Ruae',
      questionNumber: 1,
      answer: 'short answer',
      mode: 'quote',
    },
  });
  assert.equal(blocked.response.status, 429);
  assert.equal(blocked.data.ok, false);
});
