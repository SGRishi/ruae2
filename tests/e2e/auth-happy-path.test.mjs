import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createApiHandler, createMemoryStore, __test } from '../../worker.js';

const authClientSource = await readFile(
  new URL('../../public/auth-client.js', import.meta.url),
  'utf8'
);

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

function createApiFetch(handler, env, cookieJar) {
  return async function fetchImpl(url, init = {}) {
    const headers = new Headers(init.headers || {});
    const cookie = cookieHeader(cookieJar);
    if (cookie) headers.set('Cookie', cookie);
    if (!headers.has('Origin')) {
      headers.set('Origin', 'https://rishisubjects.co.uk');
    }

    const request = new Request(String(url), {
      method: init.method || 'GET',
      headers,
      body: init.body,
    });

    const response = await handler.fetch(request, env);
    applySetCookies(cookieJar, getSetCookies(response));
    return response;
  };
}

function loadAuthClient(fetchImpl) {
  const window = {
    location: { hostname: 'rishisubjects.co.uk' },
    __APP_CONFIG__: { API_BASE: 'https://api.rishisubjects.co.uk' },
  };

  const context = vm.createContext({
    window,
    fetch: fetchImpl,
    Headers,
    Response,
    Request,
    URL,
    setTimeout,
    clearTimeout,
  });

  vm.runInContext(authClientSource, context);
  return window.RuaeApi;
}

test('frontend auth client + worker handler complete happy path', async () => {
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: createMemoryStore(),
  };

  const handler = createApiHandler();
  const cookieJar = new Map();
  const api = loadAuthClient(createApiFetch(handler, env, cookieJar));

  const me1 = await api.apiRequest('/api/auth/me');
  assert.equal(me1.response.status, 200);
  assert.equal(me1.data.authenticated, false);
  assert.equal(Boolean(cookieJar.get('ruae_csrf')), true);

  const register = await api.apiRequest('/api/auth/register', {
    method: 'POST',
    csrf: true,
    json: {
      email: 'e2e-user@example.com',
      password: 'StrongPassword123',
    },
  });
  assert.equal(register.response.status, 201);
  assert.equal(register.data.ok, true);

  const login = await api.apiRequest('/api/auth/login', {
    method: 'POST',
    csrf: true,
    json: {
      email: 'e2e-user@example.com',
      password: 'StrongPassword123',
    },
  });
  assert.equal(login.response.status, 200);
  assert.equal(Boolean(cookieJar.get('ruae_session')), true);

  const protectedOk = await api.apiRequest('/api/protected/example');
  assert.equal(protectedOk.response.status, 200);
  assert.equal(protectedOk.data.ok, true);

  const logout = await api.apiRequest('/api/auth/logout', {
    method: 'POST',
    csrf: true,
    json: {},
  });
  assert.equal(logout.response.status, 200);
  assert.equal(Boolean(cookieJar.get('ruae_session')), false);

  const protectedAfter = await api.apiRequest('/api/protected/example');
  assert.equal(protectedAfter.response.status, 401);
});
