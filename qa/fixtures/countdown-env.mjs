import { createMemoryCountdownStore } from '../../worker.js';

export const QA_COUNTDOWN_SECRETS = {
  SESSION_SECRET: 'test-session-secret',
  PASSWORD_PEPPER: 'test-pepper',
};

export function qaBaseUrl(port = 8789) {
  return `http://127.0.0.1:${Number(port)}`;
}

export function createCountdownQaEnv(origin) {
  const allowedOrigins = new Set(['https://rishisubjects.co.uk']);
  if (origin) {
    allowedOrigins.add(origin);
    try {
      const parsed = new URL(origin);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        if (parsed.hostname === '127.0.0.1') {
          allowedOrigins.add(`${parsed.protocol}//localhost${parsed.port ? `:${parsed.port}` : ''}`);
        }
        if (parsed.hostname === 'localhost') {
          allowedOrigins.add(`${parsed.protocol}//127.0.0.1${parsed.port ? `:${parsed.port}` : ''}`);
        }
      }
    } catch {
      // Ignore malformed origin in QA fixtures.
    }
  }

  const env = {
    ...QA_COUNTDOWN_SECRETS,
    ALLOWED_ORIGINS: Array.from(allowedOrigins).join(','),
    OPENAI_API_KEY: 'qa-openai-test-key',
    OPENAI_MODEL: 'gpt-4o-mini',
    COUNTDOWN_STORE: createMemoryCountdownStore(),
  };

  return { env, fixtures: { origin } };
}
