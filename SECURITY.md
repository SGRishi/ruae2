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
