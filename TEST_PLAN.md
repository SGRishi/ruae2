# Manual Test Plan

## Scope

Validate production countdown flow for:

- `https://rishisubjects.co.uk` (Pages)
- `https://api.rishisubjects.co.uk` (Worker API)

## Preconditions

- Worker deployed with required secrets (`SESSION_SECRET`, `PASSWORD_PEPPER`).
- D1 schema applied.
- Pages built with `API_BASE=https://api.rishisubjects.co.uk`.

## Test Cases

1. Health endpoint

- Open `https://api.rishisubjects.co.uk/api/health`
- Expect `200` JSON with `ok: true`.

2. Countdown page loads

- Open `https://rishisubjects.co.uk/countdown/`
- Expect countdown controls and timer display to render.

3. Public countdown create + share

- Create a public countdown.
- Open the generated share link in a private/incognito window.
- Expect timer display without password prompt.

4. Private countdown create + access

- Create a private countdown with a password.
- Open private link in a private/incognito window.
- Expect password prompt, then successful unlock after entering the password.

5. Owner edit token behavior

- Keep the owner link open.
- Update title/deadline/visibility.
- Refresh and confirm changes persist.

6. Legacy routes are disabled

- Open `/maths`, `/ruae`, `/login`, and `/admin`.
- Expect `404` for all routes.

7. CORS enforcement

- From disallowed origin, API calls should fail with `403` / missing CORS success.

8. Error handling

- Send invalid JSON to countdown endpoints.
- Expect `400` safe JSON error without stack trace.

9. OpenAI date resolver fallback

- Call `/api/resolve-event-date` with and without `OPENAI_API_KEY`.
- Expect successful parsed date when configured and a controlled error when not configured.

## Automation Cross-check

Run locally before release:

```bash
npm run qa
```
