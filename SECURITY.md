# Security Checklist

## Countdown API

- [x] Explicit CORS allow-list (`ALLOWED_ORIGINS`)
- [x] No wildcard CORS with credentials
- [x] `Access-Control-Allow-Credentials: true`
- [x] Security headers on API responses

## Countdown Privacy

- [x] Owner token required for timer owner actions
- [x] Private countdowns require a password
- [x] Password hashes derived with PBKDF2 + salt (+ optional pepper)
- [x] Private viewer access cookie is signed and short-lived

## Secrets

- [x] `SESSION_SECRET` used to sign private access cookies
- [x] `PASSWORD_PEPPER` supported for password derivation hardening
- [x] `OPENAI_API_KEY` kept server-side only

## Operational Recommendations

- Rotate `SESSION_SECRET` and `PASSWORD_PEPPER` periodically.
- Restrict `ALLOWED_ORIGINS` to production domains.
- Keep `ALLOW_LOCALHOST_ORIGINS=false` in production.
- Monitor `/api/resolve-date` usage and upstream failure rates.
