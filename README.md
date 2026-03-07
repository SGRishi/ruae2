# Countdown Website + Worker API

Production deployment targets:

- Frontend: Cloudflare Pages on `https://rishisubjects.co.uk`
- API: Cloudflare Worker on `https://api.rishisubjects.co.uk` (`/api/*`)

## Stack

- Runtime: Node.js (ESM) + Cloudflare Workers
- Package manager: npm
- Frontend: static HTML/CSS/JS in `public/`
- API: `worker.js`
- Database: Cloudflare D1 (`d1/schema.sql`)
- Build output: `dist/`

## Repository Layout

- `public/`: countdown frontend and assets
- `public/countdown/`: countdown app (`/countdown/`)
- `worker.js`: countdown API and shared server logic
- `d1/schema.sql`: D1 schema
- `scripts/build-frontend.mjs`: frontend build script
- `scripts/smoke-deploy.sh`: deployed smoke test
- `tests/`: unit, integration, and e2e tests

## App Routes

- `/` and `/countdown/`: countdown UI
- `/countdown/:id`: shared countdown links
- `/api/health`: API health
- `/api/time`: server clock
- `/api/resolve-date`: natural-language date resolver
- `/api/resolve-event-date`: event-date resolver
- `/api/countdown/timer`: create/read/update countdown timers
- `/api/countdown/access`: private countdown access token flow

Legacy non-countdown routes are intentionally removed and return `404`.

## Setup

```bash
npm ci
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

Optional:

- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default: `gpt-4o-mini`)
- `ALLOWED_ORIGINS` (CSV list)
- `ALLOW_LOCALHOST_ORIGINS` (`true` / `false`)

## Local Development

```bash
npm run dev
```

For test-mode Worker config:

```bash
npm run dev:test
```

To build and preview static output:

```bash
npm run preview
```

## QA Gate

`npm run qa` is the required quality gate. It runs:

- `npm run test:unit`
- `npm run test:smoke`
- `npm run test:e2e`

## Deployment

See `DEPLOY.md` for Cloudflare Pages + Worker deployment steps.
