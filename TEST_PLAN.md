# Manual Test Plan

## Scope

Validate production auth flow for:

- `https://rishisubjects.co.uk` (Pages)
- `https://api.rishisubjects.co.uk` (Worker API)

## Preconditions

- Worker deployed with required secrets.
- D1 schema applied.
- Pages built with `API_BASE=https://api.rishisubjects.co.uk`.

## Test Cases

1. Health endpoint

- Open `https://api.rishisubjects.co.uk/api/health`
- Expect `200` JSON with `ok: true`.

2. Anonymous user state

- Open `https://rishisubjects.co.uk/login/`
- Network call to `/api/auth/me` should return `authenticated: false`.

3. Register user

- Submit register form with valid email/password.
- Expect success status message.

4. Login user

- Submit login form.
- Expect redirect to `/ruae/`.
- Confirm session cookie exists for `api.rishisubjects.co.uk`.

5. Session persistence

- Refresh `/ruae/`.
- User remains logged in.
- `/api/auth/me` returns `authenticated: true`.

6. Protected API access

- Call `/api/protected/example` in browser devtools or curl with cookies.
- Expect `200` and authenticated user payload.

7. Logout

- Click logout from `/ruae/`.
- Expect redirect/login state.
- `/api/protected/example` should return `401`.

8. CORS enforcement

- From disallowed origin, API calls should fail with `403` / missing CORS success.

9. CSRF enforcement

- Remove `X-CSRF-Token` on login/logout/register requests.
- Expect `403`.

10. Error handling

- Send invalid JSON to auth endpoints.
- Expect `400` safe JSON error without stack trace.

11. Admin approval/denial flow

- Open `https://rishisubjects.co.uk/admin/`.
- Enter `ADMIN_KEY`.
- Confirm pending user appears and can be approved.
- Confirm denied user cannot log in and cannot re-register.

## Automation Cross-Check

Run locally before release:

```bash
npm run lint
npm run typecheck
npm run format:check
npm run test
npm run build
npm run smoke:deploy
```
