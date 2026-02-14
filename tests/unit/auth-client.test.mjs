import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const authClientSource = await readFile(new URL('../../public/auth-client.js', import.meta.url), 'utf8');

function createJsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

function loadAuthClient({ hostname, appConfigApiBase = '', fetchImpl }) {
  const window = {
    location: { hostname },
    __APP_CONFIG__: { API_BASE: appConfigApiBase },
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

test('auth client falls back to canonical API base on production hosts', async () => {
  const api = loadAuthClient({
    hostname: 'www.rishisubjects.co.uk',
    fetchImpl: async () => createJsonResponse({ ok: true }),
  });

  assert.equal(api.getApiBase(), 'https://api.rishisubjects.co.uk');
});

test('csrf request bootstraps token from /api/auth/me when missing', async () => {
  const calls = [];
  const api = loadAuthClient({
    hostname: 'rishisubjects.co.uk',
    fetchImpl: async (url, init = {}) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith('/api/auth/me')) {
        return createJsonResponse({ ok: true, csrfToken: 'token-from-me' });
      }
      return createJsonResponse({ ok: true, csrfToken: 'token-after-login' });
    },
  });

  const { response } = await api.apiRequest('/api/auth/login', {
    method: 'POST',
    csrf: true,
    json: { email: 'user@example.com', password: 'TestPassword1234A' },
  });

  assert.equal(response.status, 200);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, 'https://api.rishisubjects.co.uk/api/auth/me');
  assert.equal(calls[1].url, 'https://api.rishisubjects.co.uk/api/auth/login');
  const csrfHeader = new Headers(calls[1].init.headers).get('x-csrf-token');
  assert.equal(csrfHeader, 'token-from-me');
});

test('csrf failure triggers one refresh + retry', async () => {
  const calls = [];
  const api = loadAuthClient({
    hostname: 'rishisubjects.co.uk',
    fetchImpl: async (url, init = {}) => {
      calls.push({ url: String(url), init });
      const idx = calls.length;
      if (idx === 1) {
        return createJsonResponse({ ok: false, error: 'Security check failed.' }, 403);
      }
      if (idx === 2) {
        return createJsonResponse({ ok: true, csrfToken: 'refreshed-token' }, 200);
      }
      return createJsonResponse({ ok: true, csrfToken: 'post-retry-token' }, 200);
    },
  });

  api.setCsrfToken('stale-token');

  const { response } = await api.apiRequest('/api/auth/logout', {
    method: 'POST',
    csrf: true,
    json: {},
  });

  assert.equal(response.status, 200);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].url, 'https://api.rishisubjects.co.uk/api/auth/logout');
  assert.equal(calls[1].url, 'https://api.rishisubjects.co.uk/api/auth/me');
  assert.equal(calls[2].url, 'https://api.rishisubjects.co.uk/api/auth/logout');
  assert.equal(new Headers(calls[2].init.headers).get('x-csrf-token'), 'refreshed-token');
});
