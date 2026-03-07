import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiHandler, createMemoryCountdownStore } from '../../worker.js';

function createRequest(path, method = 'GET') {
  return new Request(`https://api.rishisubjects.co.uk${path}`, {
    method,
    headers: {
      Origin: 'https://rishisubjects.co.uk',
      'Content-Type': 'application/json',
    },
    body: method === 'POST' ? '{}' : undefined,
  });
}

test('non-countdown website APIs are disabled', async () => {
  const handler = createApiHandler();
  const env = {
    SESSION_SECRET: 'test-session-secret',
    PASSWORD_PEPPER: 'test-pepper',
    ALLOWED_ORIGINS: 'https://rishisubjects.co.uk',
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };

  const checks = [
    ['/api/auth/me', 'GET'],
    ['/api/auth/register', 'POST'],
    ['/api/auth/login', 'POST'],
    ['/api/auth/logout', 'POST'],
    ['/api/admin/review', 'GET'],
    ['/api/maths/years', 'GET'],
    ['/api/match', 'POST'],
  ];

  for (const [path, method] of checks) {
    const response = await handler.fetch(createRequest(path, method), env);
    const data = await response.json();
    assert.equal(response.status, 404, `${method} ${path} should return 404`);
    assert.equal(data.ok, false);
  }
});
