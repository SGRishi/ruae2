import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createApiHandler,
  createMemoryStore,
  createMathsMemoryStore,
  __test,
} from '../../worker.js';
import { createMemoryAssets } from '../../qa/fixtures/memory-assets.mjs';

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

async function apiBytes(handler, env, cookieJar, path, options = {}) {
  const { response } = await apiCall(handler, env, cookieJar, path, {
    ...options,
    origin: options.origin ?? 'https://rishisubjects.co.uk',
  });
  const bytes = new Uint8Array(await response.arrayBuffer());
  return { response, bytes };
}

test('GET /api/maths/crops/:id.png returns image/png and non-zero bytes', async () => {
  const handler = createApiHandler();

  const assets = createMemoryAssets();
  const initialKey = 'maths/crops/2023/2/q_2023_2_1/q_01.png';
  const pngBytes = Uint8Array.from(
    Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/lGv9owAAAABJRU5ErkJggg==',
      'base64'
    )
  );
  await assets.put(initialKey, pngBytes, { metadata: { contentType: 'image/png' } });

  const mathsStore = createMathsMemoryStore({
    questions: [
      {
        id: 'q_2023_2_1',
        year: 2023,
        paperNumber: 2,
        qNumber: 1,
        qLabel: 'Question 1',
        topic: 'algebra',
        textExtracted: 'Solve for x',
      },
    ],
    crops: [
      {
        id: 'crop_q_2023_2_1_question_01',
        questionId: 'q_2023_2_1',
        kind: 'question',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: initialKey,
      },
    ],
  });

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    REQUIRE_MANUAL_APPROVAL: 'false',
    AUTH_STORE: createMemoryStore(),
    MATHS_STORE: mathsStore,
    MATHS_ASSETS: assets,
  };

  const jar = new Map();

  const me = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me.response.status, 200);
  let csrfToken = me.data.csrfToken;

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

  const question = await apiCall(handler, env, jar, '/api/maths/question?id=q_2023_2_1');
  assert.equal(question.response.status, 200);
  const cropId = question.data.question.questionCrops[0].id;

  const png = await apiBytes(
    handler,
    env,
    jar,
    `/api/maths/crops/${encodeURIComponent(cropId)}.png`
  );
  assert.equal(png.response.status, 200);
  assert.equal((png.response.headers.get('content-type') || '').includes('image/png'), true);
  assert.ok(png.bytes.byteLength > 0);
});

test('review save updates crop rect + regenerates crop blob', async () => {
  const handler = createApiHandler();

  const assets = createMemoryAssets();
  const oldKey = 'maths/crops/2023/2/q_2023_2_1/q_01.png';
  const pngBytes = Uint8Array.from(
    Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/lGv9owAAAABJRU5ErkJggg==',
      'base64'
    )
  );
  await assets.put(oldKey, pngBytes, { metadata: { contentType: 'image/png' } });

  const mathsStore = createMathsMemoryStore({
    questions: [
      {
        id: 'q_2023_2_1',
        year: 2023,
        paperNumber: 2,
        qNumber: 1,
        qLabel: 'Question 1',
        topic: 'algebra',
        textExtracted: 'Solve for x',
      },
    ],
    crops: [
      {
        id: 'crop_q_2023_2_1_question_01',
        questionId: 'q_2023_2_1',
        kind: 'question',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: oldKey,
      },
    ],
  });

  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    REQUIRE_MANUAL_APPROVAL: 'false',
    AUTH_STORE: createMemoryStore(),
    MATHS_STORE: mathsStore,
    MATHS_ASSETS: assets,
  };

  const jar = new Map();

  const me = await apiCall(handler, env, jar, '/api/auth/me');
  assert.equal(me.response.status, 200);
  let csrfToken = me.data.csrfToken;

  const register = await apiCall(handler, env, jar, '/api/auth/register', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'reviewuser', password: 'StrongPassword123' },
  });
  assert.equal(register.response.status, 201);

  const login = await apiCall(handler, env, jar, '/api/auth/login', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: { username: 'reviewuser', password: 'StrongPassword123' },
  });
  assert.equal(login.response.status, 200);
  if (typeof login.data.csrfToken === 'string' && login.data.csrfToken) {
    csrfToken = login.data.csrfToken;
  }

  const before = await apiCall(handler, env, jar, '/api/maths/question?id=q_2023_2_1');
  assert.equal(before.response.status, 200);
  const crop = before.data.question.questionCrops[0];
  assert.equal(crop.storageKey, oldKey);

  const beforePng = await apiBytes(
    handler,
    env,
    jar,
    `/api/maths/crops/${encodeURIComponent(crop.id)}.png`
  );
  assert.equal(beforePng.response.status, 200);

  const save = await apiCall(handler, env, jar, '/api/maths/review/save', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    json: {
      questionId: 'q_2023_2_1',
      question: { qLabel: 'Question 1', topic: 'algebra' },
      crops: [
        {
          id: crop.id,
          x0: 10,
          y0: 11,
          x1: 120,
          y1: 121,
          imageBase64: `data:image/png;base64,${Buffer.from(pngBytes).toString('base64')}`,
          contentType: 'image/png',
        },
      ],
    },
  });
  assert.equal(save.response.status, 200);
  assert.equal(save.data.ok, true);
  assert.equal(save.data.updatedCrops, 1);
  assert.equal(save.data.uploaded, 1);

  const after = await apiCall(handler, env, jar, '/api/maths/question?id=q_2023_2_1');
  assert.equal(after.response.status, 200);
  const updated = after.data.question.questionCrops[0];
  assert.equal(updated.x0, 10);
  assert.equal(updated.y0, 11);
  assert.equal(updated.x1, 120);
  assert.equal(updated.y1, 121);
  assert.notEqual(updated.storageKey, oldKey);

  const newKey = updated.storageKey;
  assert.equal(assets.__unsafe_listKeys().includes(newKey), true);

  const afterPng = await apiBytes(
    handler,
    env,
    jar,
    `/api/maths/crops/${encodeURIComponent(updated.id)}.png`
  );
  assert.equal(afterPng.response.status, 200);
  assert.ok(afterPng.bytes.byteLength > 0);

  const stored = await assets.getWithMetadata(newKey, { type: 'arrayBuffer' });
  assert.ok(stored && stored.value);
  assert.equal(afterPng.bytes.byteLength, new Uint8Array(stored.value).byteLength);
});
