# RUAE Pages + Worker Stack

This repo is production-ready for:
- Cloudflare Pages frontend on `https://rishisubjects.co.uk`
- Cloudflare Worker API on `https://<worker>.workers.dev` and `https://api.rishisubjects.co.uk`

## Architecture

- `public/`: static frontend (home, login, RUAE app)
- `worker.js`: API/auth Worker (`/api/*`)
- `d1/schema.sql`: D1 schema (users, sessions, rate limits, lockouts)
- `scripts/build-frontend.mjs`: copies `public/` to `dist/` and injects runtime `API_BASE`
- `tests/`: unit + integration tests for auth/security flow

## Auth Model Choice

This deployment uses **HTTP-only cookie sessions** with CSRF protection.

Reason:
- Pages site on `rishisubjects.co.uk` and Worker on `api.rishisubjects.co.uk` are same-site.
- Cookie sessions with `SameSite=Lax` + `Secure` avoid localStorage token risks.
- CSRF is enforced for mutating API routes via `X-CSRF-Token` + cookie token match + origin checks.

`workers.dev` remains usable for direct API checks, but browser auth should use `api.rishisubjects.co.uk`.

## API Endpoints

- `GET /api/health`
- `GET /api/auth/me`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/protected/example`
- `POST /api/match` (authenticated RUAE AI helper)

All responses are JSON and include consistent status codes.

## Environment Variables

### Cloudflare Pages (build-time)

Set one of:
- `API_BASE`
- `VITE_API_BASE`
- `NEXT_PUBLIC_API_BASE`

`npm run build` automatically picks the first non-empty value in that order.

### Cloudflare Worker (runtime)

Required secrets:
- `SESSION_SECRET`
- `PASSWORD_PEPPER`

Optional secrets:
- `OPENAI_API_KEY`

Optional vars:
- `OPENAI_MODEL` (default `gpt-4o-mini`)
- `ALLOWED_ORIGINS` (CSV, default includes `https://rishisubjects.co.uk`)
- `PAGES_PROJECT_NAME` (enables `https://*.{project}.pages.dev` preview origins)
- `REQUIRE_MANUAL_APPROVAL` (`true`/`false`)
- `ALLOW_LOCALHOST_ORIGINS` (`true`/`false`)

## Local Development

1. Apply schema to local D1:

```bash
npx wrangler d1 execute ruae-members-db --local --file d1/schema.sql
```

2. Run Worker locally:

```bash
npx wrangler dev --port 8787
```

3. Build frontend pointed to local Worker:

```bash
API_BASE=http://127.0.0.1:8787 npm run build
```

4. Serve frontend:

```bash
python3 -m http.server 8788 -d dist
```

Then open `http://127.0.0.1:8788`.

## Quality Gates

```bash
npm run lint
npm run test
npm run build
```

## Deployment Docs

- `DEPLOY.md`
- `SECURITY.md`
- `TEST_PLAN.md`
