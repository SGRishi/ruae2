# Deployment Guide (Cloudflare Pages + Worker)

## 1) Deploy Worker API

1. Authenticate:

```bash
npx wrangler login
```

For non-interactive CI, set `CLOUDFLARE_API_TOKEN` with least-privilege scopes documented in `SECURITY.md`.

2. Ensure D1 schema is applied:

```bash
npx wrangler d1 execute ruae-members-db --file d1/schema.sql
```

3. Set Worker secrets:

```bash
npx wrangler secret put SESSION_SECRET
npx wrangler secret put PASSWORD_PEPPER
npx wrangler secret put ADMIN_LINK_TOKEN
npx wrangler secret put OPENAI_API_KEY
```

4. (Maths) Ensure KV storage exists for PDF + crop assets:

- Create a KV namespace (one-time):

```bash
npx wrangler kv namespace create MATHS_ASSETS
```

- Add the resulting `[[kv_namespaces]]` binding to `wrangler.toml` as `binding = "MATHS_ASSETS"`.

5. Deploy Worker:

```bash
npx wrangler deploy
```

6. Confirm endpoints:

```bash
curl -i https://<your-worker>.workers.dev/api/health
curl -i https://api.rishisubjects.co.uk/api/health
```

## 2) Deploy Pages Frontend

In Cloudflare Pages project settings:

- Framework preset: `None`
- Build command: `npm run build`
- Build output directory: `dist`

Set build env var:

- `API_BASE=https://api.rishisubjects.co.uk`

(Equivalent alternatives also supported: `VITE_API_BASE` or `NEXT_PUBLIC_API_BASE`.)

Deploy the project.

CLI alternative:

```bash
npm run build
npx wrangler pages deploy dist --project-name rishisubjects
```

## 2b) Publish Maths Data (Optional but Required for /maths Content)

The `/maths/` UI reads from D1 + KV. To populate it:

1. Install Python deps:

```bash
python3 -m venv .venv
./.venv/bin/pip install -r maths/requirements.txt
```

2. Ingest + segment PDFs locally (idempotent):

```bash
./.venv/bin/python -m maths ingest <folder>
./.venv/bin/python -m maths segment
```

3. Publish to production:

```bash
./.venv/bin/python -m maths publish
```

## 3) Configure Domains

- Pages custom domain: `rishisubjects.co.uk`
- Worker custom domain route: `api.rishisubjects.co.uk`
  - Custom domains must be hostname-only (no `/*` path suffix).

`wrangler.toml` already includes route + workers.dev enabled.

## 4) Set Worker Vars

Configure Worker vars in Cloudflare dashboard or wrangler:

- `ALLOWED_ORIGINS=https://rishisubjects.co.uk`
- `PAGES_PROJECT_NAME=rishisubjects`
- `REQUIRE_MANUAL_APPROVAL=true`
- `ALLOW_LOCALHOST_ORIGINS=true` (optional for local testing)

Admin route:

- `https://rishisubjects.co.uk/admin/#token=<ADMIN_LINK_TOKEN>`
- Keep this URL private; it grants admin review/approve/deny access.

## 5) Post-Deploy Smoke Checks

1. `GET /api/health` is `200`.
2. Open `https://rishisubjects.co.uk/login/`.
3. Register new user.
4. Login succeeds and redirects to `/ruae/`.
5. `GET /api/auth/me` returns `authenticated: true`.
6. `GET /api/protected/example` returns `200`.
7. Logout clears session and protected endpoint returns `401`.

Automated smoke test:

```bash
npm run smoke:deploy
```

GitHub Actions smoke workflow:

- `.github/workflows/smoke-deploy.yml`
