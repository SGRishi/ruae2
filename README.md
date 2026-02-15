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
- `public/admin/`: admin approval UI (`/admin/`)
- `public/ruae/`: RUAE practice UI (`/ruae/`)
- `public/maths/`: SQA Maths past-paper question bank UI (`/maths/`)
- `worker.js`: Worker API with auth, CSRF, rate limiting, RUAE match endpoint
- `d1/schema.sql`: D1 schema
- `maths/`: maths ingestion + segmentation CLI pipeline (local SQLite + publish to Cloudflare)
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
- `ADMIN_LINK_TOKEN` (long random token embedded in private `/admin/#token=...` link)

Optional secret:

- `OPENAI_API_KEY`

Optional vars:

- `OPENAI_MODEL` (default: `gpt-4o-mini`)
- `ALLOWED_ORIGINS` (CSV list)
- `PAGES_PROJECT_NAME`
- `REQUIRE_MANUAL_APPROVAL` (`true` / `false`)
- `ALLOW_LOCALHOST_ORIGINS` (`true` / `false`)

For approval workflow, set `REQUIRE_MANUAL_APPROVAL=true`.

Auth identifier:

- Users register/login with `username` (first name, letters only) + password.
- Backend keeps legacy `email` request field support for compatibility, but UI uses username.

## Admin Approval Flow

1. User signs up at `/login/` with first-name username + password and stays in `pending` status.
2. Admin opens `/admin/#token=<ADMIN_LINK_TOKEN>` (or `/admin/?token=<ADMIN_LINK_TOKEN>`).
3. Admin approves or denies users.
4. Approved users can log in; denied users are blocked from login and registration.

## Apps / Routes

- `/ruae/`: existing RUAE practice site (unchanged)
- `/maths/`: SQA Maths Past Paper Question Bank (protected by the same auth + approval rules)
- `/api/maths/*`: backend API for the Maths question bank (approved users only)

## Maths Pipeline (Ingest + Segment + Publish)

The Maths question bank is powered by a local pipeline that:

- indexes PDFs into a local SQLite DB (same schema as D1)
- segments questions + marking-instruction blocks
- renders crop PNGs
- publishes rows to D1 + assets to KV (`MATHS_ASSETS`)

Python env (one-time):

```bash
python3 -m venv .venv
./.venv/bin/pip install -r maths/requirements.txt
```

Ingest PDFs (idempotent):

```bash
./.venv/bin/python -m maths ingest <folder>
```

Segment + generate crops:

```bash
./.venv/bin/python -m maths segment
```

Publish to production (uploads assets + upserts D1 rows):

```bash
./.venv/bin/python -m maths publish
```

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

## Running QA

`npm run qa` is the single command that gates Maths QA. It runs:

- `npm run test:unit` (Node unit + integration tests under `tests/`)
- `npm run test:smoke` (seeded fixture smoke checks for `/api/maths/*` + crop rendering)
- `npm run test:e2e` (Playwright UI tests under `qa/e2e/`)

Playwright browser install (one-time on a machine/CI image):

```bash
npx playwright install --with-deps
```

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
