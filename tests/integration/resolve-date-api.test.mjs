import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiHandler } from '../../worker.js';

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

function createApiRequest(path) {
  return new Request(`https://api.rishisubjects.co.uk${path}`, {
    method: 'GET',
    headers: {
      Origin: 'https://rishisubjects.co.uk',
    },
  });
}

test('resolve-date API uses Responses web_search and returns explicit source URL', async (t) => {
  const fixedNow = Date.UTC(2026, 0, 1, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });

  let openAiCalls = 0;
  let openAiBody = null;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    if (String(url) !== 'https://api.openai.com/v1/responses') {
      throw new Error(`Unexpected fetch URL: ${String(url)}`);
    }
    openAiCalls += 1;
    openAiBody = JSON.parse(String(init.body || '{}'));

    return jsonResponse({
      output_text: JSON.stringify({
        title: 'SQA Higher Mathematics exam',
        datetime_iso: '2026-05-05T08:00:00.000Z',
        timezone: 'Europe/London',
        source_url: 'https://www.sqa.org.uk/sqa/107652.html',
        source_title: 'SQA - Exam Timetable',
        confidence: 'high',
        note: 'Resolved from official SQA timetable.',
      }),
    });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const response = await handler.fetch(
    createApiRequest(
      '/api/resolve-date?q=SQA%20Higher%20maths%20exam%20day&timezone=Europe/London'
    ),
    {
      OPENAI_API_KEY: 'test-openai-key',
    }
  );

  const data = await response.json();

  assert.equal(response.status, 200);
  assert.equal(data.query, 'SQA Higher maths exam day');
  assert.equal(data.title, 'SQA Higher Mathematics exam');
  assert.equal(data.datetime_iso, '2026-05-05T08:00:00.000Z');
  assert.equal(data.timezone, 'Europe/London');
  assert.equal(data.source_url, 'https://www.sqa.org.uk/sqa/107652.html');
  assert.equal(data.source_title, 'SQA - Exam Timetable');
  assert.equal(data.retrieved_at_utc, '2026-01-01T12:00:00.000Z');
  assert.equal(data.confidence, 'high');
  assert.equal(openAiCalls, 1);

  assert.ok(Array.isArray(openAiBody.tools));
  assert.ok(openAiBody.tools.some((tool) => tool && tool.type === 'web_search_preview'));
  assert.match(String(openAiBody.instructions || ''), /authoritative/i);
});

test('resolve-date API caches successful lookups for repeated query+timezone requests', async (t) => {
  const fixedNow = Date.UTC(2026, 0, 2, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });

  let openAiCalls = 0;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url) !== 'https://api.openai.com/v1/responses') {
      throw new Error(`Unexpected fetch URL: ${String(url)}`);
    }
    openAiCalls += 1;
    return jsonResponse({
      output_text: JSON.stringify({
        title: 'Cache verification event',
        datetime_iso: '2026-09-01T09:00:00.000Z',
        timezone: 'Europe/London',
        source_url: 'https://www.gov.uk',
        source_title: 'GOV.UK',
        confidence: 'medium',
        note: null,
      }),
    });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const query = encodeURIComponent('cache verification event unique key');
  const first = await handler.fetch(
    createApiRequest(`/api/resolve-date?q=${query}&timezone=Europe/London`),
    {
      OPENAI_API_KEY: 'test-openai-key',
    }
  );
  const second = await handler.fetch(
    createApiRequest(`/api/resolve-date?q=${query}&timezone=Europe/London`),
    {
      OPENAI_API_KEY: 'test-openai-key',
    }
  );

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(openAiCalls, 1);
});

test('resolve-date API returns clear error when no reliable source is found', async (t) => {
  const fixedNow = Date.UTC(2026, 0, 3, 12, 0, 0);
  const handler = createApiHandler({ now: () => fixedNow });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url) !== 'https://api.openai.com/v1/responses') {
      throw new Error(`Unexpected fetch URL: ${String(url)}`);
    }
    return jsonResponse({
      output_text: JSON.stringify({
        title: 'Unverified event',
        datetime_iso: null,
        timezone: 'Europe/London',
        source_url: null,
        source_title: null,
        confidence: 'low',
        note: 'No authoritative source provides a concrete date.',
      }),
    });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const response = await handler.fetch(createApiRequest('/api/resolve-date?q=unknown%20event'), {
    OPENAI_API_KEY: 'test-openai-key',
  });
  const data = await response.json();

  assert.equal(response.status, 422);
  assert.match(String(data.error || ''), /no reliable source/i);
});
