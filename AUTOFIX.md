# AUTOFIX

## Local autonomous loop (recommended)

Run local dev + Playwright, then commit/push if green:

```bash
DEV_CMD="npm run preview" LOCAL_URL="http://127.0.0.1:3000/countdown" npm run autofix:local
```

Notes:
- `autofix:local` only runs fixes/tests against local code and local tests.
- If local tests fail, the script stops and expects one manual fix attempt before rerun.

## Local test once (no commit/push)

```bash
DEV_CMD="npm run preview" LOCAL_URL="http://127.0.0.1:3000/countdown" npm run test:local
```

## Live smoke test (read-only)

```bash
LIVE_URL="https://rishisubjects.co.uk/countdown" npm run smoke:live
```

Notes:
- Live smoke is read-only and uses `tests/e2e/live-smoke.spec.ts`.
- Production failures from smoke do **not** trigger auto-fix.
