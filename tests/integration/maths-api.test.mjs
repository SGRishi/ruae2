import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createApiHandler,
  createMemoryStore,
  createMathsMemoryStore,
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

async function sha256Base64Url(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const raw = new Uint8Array(digest);
  let bin = '';
  for (let i = 0; i < raw.length; i += 1) {
    bin += String.fromCharCode(raw[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

test('maths endpoints require approved auth', async () => {
  const handler = createApiHandler();

  const seedMaths = createMathsMemoryStore({
    questions: [
      {
        id: 'q_2023_2_1',
        year: 2023,
        paperNumber: 2,
        qNumber: 1,
        qLabel: 'Question 1',
        topic: 'algebra',
        textExtracted: 'Solve for x',
        thumbUrl: '/example-thumb.png',
      },
    ],
    crops: [
      {
        id: 'crop_q1',
        questionId: 'q_2023_2_1',
        kind: 'question',
        url: '/example-q.png',
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 200,
      },
      {
        id: 'crop_a1',
        questionId: 'q_2023_2_1',
        kind: 'answer',
        url: '/example-a.png',
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 200,
      },
    ],
  });

  seedMaths.__unsafe_seedDatasheets([
    {
      year: 2023,
      paperNumber: 2,
      fileId: 'ds_2023_2',
    },
  ]);

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    REQUIRE_MANUAL_APPROVAL: 'false',
    AUTH_STORE: createMemoryStore(),
    MATHS_STORE: seedMaths,
  };

  const jar = new Map();

  const yearsNoAuth = await apiCall(handler, env, jar, '/api/maths/years');
  assert.equal(yearsNoAuth.response.status, 401);

  const me = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me.response.status, 200);
  const csrfToken = me.data.csrfToken;

  const register = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'mathsuser', password: 'StrongPassword123' },
  });
  assert.equal(register.response.status, 201);

  const login = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'mathsuser', password: 'StrongPassword123' },
  });
  assert.equal(login.response.status, 200);

  const years = await apiCall(handler, env, jar, '/api/maths/years');
  assert.equal(years.response.status, 200);
  assert.deepEqual(years.data.years, [2023]);

  const list = await apiCall(handler, env, jar, '/api/maths/questions?year=2023&paper=2');
  assert.equal(list.response.status, 200);
  assert.equal(Array.isArray(list.data.questions), true);
  assert.equal(list.data.questions.length, 1);
  assert.equal(list.data.questions[0].id, 'q_2023_2_1');

  const detail = await apiCall(handler, env, jar, '/api/maths/question?id=q_2023_2_1');
  assert.equal(detail.response.status, 200);
  assert.equal(detail.data.question.id, 'q_2023_2_1');
  assert.equal(detail.data.question.answerCrops.length, 1);

  const datasheet = await apiCall(handler, env, jar, '/api/maths/datasheet?year=2023&paper=2');
  assert.equal(datasheet.response.status, 200);
  assert.equal(datasheet.data.fileId, 'ds_2023_2');
  assert.equal(typeof datasheet.data.pdfUrl, 'string');
  assert.equal(datasheet.data.pdfUrl.includes('/api/maths/blob'), true);
});

test('maths endpoints block authenticated but unapproved sessions', async () => {
  const handler = createApiHandler();

  const token = 'testtoken_1234567890abcd';
  const tokenHash = await sha256Base64Url(`test-session-secret\u0000${token}`);

  const authStore = {
    async getSessionWithUser(hash) {
      if (hash !== tokenHash) return null;
      return {
        sessionId: 'sess_1',
        userId: 1,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        user: {
          id: 1,
          email: 'pending',
          status: 'pending',
        },
      };
    },
    async deleteSessionByTokenHash() {},
    async deleteExpiredSessions() {},
  };

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    AUTH_STORE: authStore,
    MATHS_STORE: createMathsMemoryStore(),
  };

  const jar = new Map([['ruae_session', token]]);
  const years = await apiCall(handler, env, jar, '/api/maths/years');
  assert.equal(years.response.status, 403);
  assert.equal(String(years.data.error || '').toLowerCase().includes('approved'), true);
});
