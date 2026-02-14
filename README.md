# RUAE Pages + Worker Stack

Production deployment targets:

- Frontend: Cloudflare Pages on `https://rishisubjects.co.uk`
- API: Cloudflare Worker on `https://api.rishisubjects.co.uk` (`/api/*`)

## Stack

- Runtime: Node.js (ESM) + Cloudflare Workers
- Package manager: npm
- Frontend: static HTML/CSS/JS in `public/`
- API/auth: `worker.js`
- Database: Cloudflare D1 (`d1/schema.sql`)
- Build output: `dist/`

## Repository Layout

- `public/`: frontend pages and assets
- `worker.js`: Worker API with auth, CSRF, rate limiting, RUAE match endpoint
- `d1/schema.sql`: D1 schema
- `scripts/build-frontend.mjs`: frontend build script
- `scripts/smoke-deploy.sh`: deployed smoke test
- `tests/`: unit, integration, and e2e tests
- `.github/workflows/`: CI and smoke workflows

## Prerequisites

- Node.js `22+` (local currently validated on Node `24.12.0`)
- npm `10+`
- Wrangler CLI (`npx wrangler ...`)

## Setup

1. Install dependencies:

```bash
npm ci
```

2. Configure local secrets:

```bash
cp .env.example .env
```

Use placeholders locally; do not commit real secrets.

3. Apply local D1 schema:

```bash
npx wrangler d1 execute ruae-members-db --local --file d1/schema.sql
```

## Environment Variables

### Frontend build-time

The build uses the first non-empty value:

- `API_BASE`
- `VITE_API_BASE`
- `NEXT_PUBLIC_API_BASE`

### Worker runtime

Required secrets:

- `SESSION_SECRET`
- `PASSWORD_PEPPER`

Optional secret:

- `OPENAI_API_KEY`

Optional vars:

- `OPENAI_MODEL` (default: `gpt-4o-mini`)
- `ALLOWED_ORIGINS` (CSV list)
- `PAGES_PROJECT_NAME`
- `REQUIRE_MANUAL_APPROVAL` (`true` / `false`)
- `ALLOW_LOCALHOST_ORIGINS` (`true` / `false`)

## Local Development

1. Run Worker locally:

```bash
npx wrangler dev --local --port 8787
```

2. Build frontend pointing at local Worker:

```bash
API_BASE=http://127.0.0.1:8787 npm run build
```

3. Serve frontend:

```bash
python3 -m http.server 8788 -d dist
```

4. Open:

- `http://127.0.0.1:8788` (frontend)
- `http://127.0.0.1:8787/api/health` (API health)

## Quality Gates

```bash
npm run lint
npm run typecheck
npm run format:check
npm test
npm run build
```

CI runs these steps on push/PR via `.github/workflows/ci.yml`.

## Deployment

See `DEPLOY.md` for full Cloudflare Pages + Worker instructions.

After deployment, run:

```bash
npm run smoke:deploy
```

GitHub smoke workflow: `.github/workflows/smoke-deploy.yml`.

## Security

- Checklist and controls: `SECURITY.md`
- Manual test plan: `TEST_PLAN.md`
- Change log: `CHANGELOG.md`
