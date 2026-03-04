# AUTOFIX

## Local autonomous loop (recommended)

Runs local dev + Playwright repeatedly (up to 8 iterations by default), then commits/pushes on success and runs read-only live smoke:

```bash
DEV_CMD="npm run preview" LOCAL_URL="http://localhost:3000/countdown" npm run autofix:local
```

Optional:

```bash
MAX_ITERATIONS=8 DEV_CMD="npm run preview" LOCAL_URL="http://localhost:3000/countdown" npm run autofix:local
```

Notes:
- `autofix:local` only runs autonomous retries against local code/tests.
- It never applies production fixes.

## Local test once (no commit/push)

```bash
DEV_CMD="npm run preview" LOCAL_URL="http://localhost:3000/countdown" npm run test:local
```

## Live smoke test (read-only)

```bash
LIVE_URL="https://rishisubjects.co.uk/countdown" npm run smoke:live
```

Notes:
- Live smoke is read-only and uses `tests/e2e/live-smoke.spec.ts`.
- Production failures from smoke do **not** trigger auto-fix.
