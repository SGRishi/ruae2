import { qaBaseUrl } from '../../fixtures/maths-env.mjs';

export async function setSessionCookie(context, token) {
  await context.addCookies([
    {
      name: 'ruae_session',
      value: String(token || ''),
      url: qaBaseUrl(),
    },
  ]);
}

