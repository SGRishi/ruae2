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

test('CORS preflight allows admin headers', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };

  const jar = new Map();
  const preflight = await apiCall(handler, env, jar, '/api/admin/review', {
    method: 'OPTIONS',
    headers: {
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'x-admin-token, content-type',
    },
  });

  assert.equal(preflight.response.status, 204);
  const allowed = preflight.response.headers.get('access-control-allow-headers') || '';
  assert.equal(allowed.toLowerCase().includes('x-admin-token'), true);
});

test('admin can review, approve, and deny accounts', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    REQUIRE_MANUAL_APPROVAL: 'true',
    ADMIN_LINK_TOKEN: 'test-admin-token-1234567890',
    AUTH_STORE: createMemoryStore(),
  };

  const jar = new Map();

  const me = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me.response.status, 200);
  let csrfToken = me.data.csrfToken;

  const register = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'pendinguser', password: 'StrongPassword123' },
  });
  assert.equal(register.response.status, 201);
  assert.equal(register.data.user.status, 'pending');

  const pendingLogin = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'pendinguser', password: 'StrongPassword123' },
  });
  assert.equal(pendingLogin.response.status, 403);

  const reviewNoKey = await apiCall(handler, env, jar, '/api/admin/review');
  assert.equal(reviewNoKey.response.status, 401);

  const reviewBadKey = await apiCall(handler, env, jar, '/api/admin/review', {
    headers: { 'X-Admin-Token': 'wrong-key' },
  });
  assert.equal(reviewBadKey.response.status, 403);

  const review = await apiCall(handler, env, jar, '/api/admin/review', {
    headers: { 'X-Admin-Token': env.ADMIN_LINK_TOKEN },
  });
  assert.equal(review.response.status, 200);
  assert.equal(Array.isArray(review.data.pendingUsers), true);
  assert.equal(Array.isArray(review.data.approvedUsers), true);
  assert.equal(
    review.data.pendingUsers.some((user) => user.username === 'pendinguser'),
    true
  );

  const approve = await apiCall(handler, env, jar, '/api/admin/approve', {
    method: 'POST',
    headers: { 'X-Admin-Token': env.ADMIN_LINK_TOKEN },
    json: { username: 'pendinguser' },
  });
  assert.equal(approve.response.status, 200);
  assert.equal(approve.data.user.status, 'approved');
  assert.equal(approve.data.user.username, 'pendinguser');

  const approvedLogin = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'pendinguser', password: 'StrongPassword123' },
  });
  assert.equal(approvedLogin.response.status, 200);
  csrfToken = approvedLogin.data.csrfToken;

  const deny = await apiCall(handler, env, jar, '/api/admin/deny', {
    method: 'POST',
    headers: { 'X-Admin-Token': env.ADMIN_LINK_TOKEN },
    json: { username: 'pendinguser', reason: 'Not approved for access.' },
  });
  assert.equal(deny.response.status, 200);
  assert.equal(deny.data.denied.username, 'pendinguser');

  const deniedLogin = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'pendinguser', password: 'StrongPassword123' },
  });
  assert.equal(deniedLogin.response.status, 403);
  assert.equal(String(deniedLogin.data.error || '').includes('denied'), true);

  const deniedRegister = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'pendinguser', password: 'StrongPassword123' },
  });
  assert.equal(deniedRegister.response.status, 403);
});
