# Security Checklist

## Auth + Session

- [x] HTTP-only session cookie (`ruae_session`)
- [x] `Secure` cookie in HTTPS environments
- [x] `SameSite=Lax` cookie policy
- [x] Server-side session storage in D1 (`sessions` table)
- [x] Session invalidation on logout
- [x] Session expiry enforcement

## CSRF

- [x] Double-submit CSRF token cookie (`ruae_csrf`)
- [x] `X-CSRF-Token` required on mutating auth routes
- [x] CSRF token compared with timing-safe comparison
- [x] Origin/referrer validation for mutating routes

## CORS

- [x] Explicit origin allow-list
- [x] No wildcard CORS with credentials
- [x] `Access-Control-Allow-Credentials: true`
- [x] Optional Pages preview origin support via `PAGES_PROJECT_NAME`

## Input Validation + Abuse Controls

- [x] Email format validation
- [x] Strong password policy (length + upper/lower/number)
- [x] JSON payload parsing with size limits
- [x] IP-based rate limiting (register/login/match)
- [x] Login lockout escalation after repeated failures

## Secrets + Errors

- [x] Secrets sourced from Cloudflare secrets/vars, not hard-coded
- [x] `.env*` ignored by git (except `.env.example`)
- [x] Safe error responses (no stack traces in API responses)

## Platform Headers

- [x] `Strict-Transport-Security`
- [x] `X-Content-Type-Options`
- [x] `Referrer-Policy`
- [x] `X-Frame-Options`
- [x] `Permissions-Policy`

## Operational Recommendations

- Rotate `SESSION_SECRET` and `PASSWORD_PEPPER` periodically.
- Restrict `ALLOWED_ORIGINS` to production domains only.
- Keep `ALLOW_LOCALHOST_ORIGINS=false` in production.
- Enable Cloudflare WAF/bot controls for `api.rishisubjects.co.uk`.

## Token Scope Requirements (Least Privilege)

Services used by this repo:

1. Cloudflare (Workers, D1, Pages, routes)
2. OpenAI API (server-side Responses API calls only)

Required Cloudflare token scopes for deploy operations:

- Account: `Workers Scripts:Edit`
- Account: `D1:Edit`
- Account: `Cloudflare Pages:Edit` (for `wrangler pages deploy`)
- Zone: `Workers Routes:Edit` (for custom domain route binding)
- Zone: `Zone:Read` (zone lookup used by Wrangler tooling)

Required OpenAI key capability:

- Permission to call `POST /v1/responses`
- Key must stay server-side only (Worker secret), never bundled to frontend

## Verified Status (2026-02-14)

- `npx wrangler whoami` reports write scopes for `workers`, `workers_routes`, `d1`, and `pages`.
- Current Cloudflare auth is a superset of required scopes; tighten to the minimum set above for least privilege where possible.
- `.env*` is git-ignored (except `.env.example`) and `.dev.vars` is ignored.
- Working tree + git history scans found no high-confidence leaked secrets.

## References

- https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/
- https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/
- https://developers.cloudflare.com/d1/platform/release-notes/
- https://platform.openai.com/docs/api-reference/responses/create
- https://help.openai.com/en/articles/8867743-assign-api-key-permissions
- https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety
