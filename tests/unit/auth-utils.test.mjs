import test from 'node:test';
import assert from 'node:assert/strict';
import { __test } from '../../worker.js';

test('email validator handles common cases', () => {
  assert.equal(__test.isValidEmail('student@example.com'), true);
  assert.equal(__test.isValidEmail('student+tag@example.co.uk'), true);
  assert.equal(__test.isValidEmail('bad-email'), false);
  assert.equal(__test.isValidEmail('missing@tld'), false);
});

test('password strength enforces upper/lower/number/min length', () => {
  assert.equal(__test.isStrongPassword('Abcdefgh1234'), true);
  assert.equal(__test.isStrongPassword('abcdefgh1234'), false);
  assert.equal(__test.isStrongPassword('ABCDEFGH1234'), false);
  assert.equal(__test.isStrongPassword('Abcdefghijkl'), false);
  assert.equal(__test.isStrongPassword('Abc123'), false);
});

test('origin allow list supports exact and pages previews', () => {
  const env = {
    ALLOWED_ORIGINS: 'https://app.example.com, https://second.example.com',
    PAGES_PROJECT_NAME: 'rishisubjects',
  };

  assert.equal(__test.isOriginAllowed('https://app.example.com', env), true);
  assert.equal(__test.isOriginAllowed('https://abc123.rishisubjects.pages.dev', env), true);
  assert.equal(__test.isOriginAllowed('https://evil.example.net', env), false);
});

test('csrf validation requires allowed origin and matching token', () => {
  const env = { ALLOWED_ORIGINS: 'https://frontend.example.com' };

  const goodReq = new Request('https://api.example.com/api/auth/login', {
    method: 'POST',
    headers: {
      Origin: 'https://frontend.example.com',
      Cookie: 'ruae_csrf=test_token_abcdefghijklmnopqrstuvwxyz',
    },
  });

  const good = __test.validateCsrf(goodReq, env, 'test_token_abcdefghijklmnopqrstuvwxyz');
  assert.equal(good.ok, true);

  const badOriginReq = new Request('https://api.example.com/api/auth/login', {
    method: 'POST',
    headers: {
      Origin: 'https://evil.example.com',
      Cookie: 'ruae_csrf=test_token_abcdefghijklmnopqrstuvwxyz',
    },
  });

  const badOrigin = __test.validateCsrf(badOriginReq, env, 'test_token_abcdefghijklmnopqrstuvwxyz');
  assert.equal(badOrigin.ok, false);

  const badToken = __test.validateCsrf(goodReq, env, 'wrong_token_abcdefghijklmnopqrstuvwxyz');
  assert.equal(badToken.ok, false);
});
