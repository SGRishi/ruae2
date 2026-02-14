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

test('CORS rejects disallowed origins', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };

  const jar = new Map();
  const result = await apiCall(handler, env, jar, '/api/auth/me', {
    origin: 'https://evil.example.com',
  });

  assert.equal(result.response.status, 403);
  assert.equal(result.data.ok, false);
});

test('register -> login -> session persistence -> logout flow', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };

  const jar = new Map();

  const me1 = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me1.response.status, 200);
  assert.equal(me1.data.authenticated, false);
  assert.equal(typeof me1.data.csrfToken, 'string');
  assert.equal(Boolean(jar.get('ruae_csrf')), true);
  let csrfToken = me1.data.csrfToken;

  const registerNoCsrf = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    json: {
      email: 'student@example.com',
      password: 'StrongPassword123',
    },
  });
  assert.equal(registerNoCsrf.response.status, 403);
  if (registerNoCsrf.data.csrfToken) {
    csrfToken = registerNoCsrf.data.csrfToken;
  }

  const register = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': csrfToken,
    },
    json: {
      email: 'student@example.com',
      password: 'StrongPassword123',
    },
  });
  assert.equal(register.response.status, 201);

  const badLogin = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': csrfToken,
    },
    json: {
      email: 'student@example.com',
      password: 'WrongPassword123',
    },
  });
  assert.equal(badLogin.response.status, 401);

  const goodLogin = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': csrfToken,
    },
    json: {
      email: 'student@example.com',
      password: 'StrongPassword123',
    },
  });
  assert.equal(goodLogin.response.status, 200);
  assert.equal(Boolean(jar.get('ruae_session')), true);
  assert.equal(typeof goodLogin.data.csrfToken, 'string');
  csrfToken = goodLogin.data.csrfToken;

  const me2 = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me2.response.status, 200);
  assert.equal(me2.data.authenticated, true);
  assert.equal(me2.data.approved, true);
  assert.equal(me2.data.user.email, 'student@example.com');

  const protectedOk = await apiCall(handler, env, jar, '/api/protected/example');
  assert.equal(protectedOk.response.status, 200);
  assert.equal(protectedOk.data.ok, true);

  const logoutNoCsrf = await apiCall(handler, env, jar, '/api/auth/logout', {
    method: 'POST',
    json: {},
  });
  assert.equal(logoutNoCsrf.response.status, 403);
  if (logoutNoCsrf.data.csrfToken) {
    csrfToken = logoutNoCsrf.data.csrfToken;
  }

  const logout = await apiCall(handler, env, jar, '/api/auth/logout', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': csrfToken,
    },
    json: {},
  });
  assert.equal(logout.response.status, 200);
  assert.equal(Boolean(jar.get('ruae_session')), false);

  const protectedAfterLogout = await apiCall(handler, env, jar, '/api/protected/example');
  assert.equal(protectedAfterLogout.response.status, 401);
});
