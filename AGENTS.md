# AGENTS.md — Codex Instructions for this Repo (ruae2)

You are an agent working on this repository. Follow these rules strictly.

## Non-negotiable Definition of Done
Do NOT claim completion unless ALL of the following are true:

1) `npm run qa` exits with code 0 (green).
2) After your final changes, re-run `npm run qa` once more and confirm it is still green.
3) No secrets or env files are added to git (see "Secrets & safety").

If `npm run qa` fails, you must fix the issue and re-run until it passes.

## What "qa" means here
The authoritative QA gate is:

- `npm run qa` (one-shot, must exit 0)

Notes:
- `npm run qa:watch` is for interactive development only and is NOT a completion gate because it does not exit.
- You may use `npm run qa:watch` while iterating, but before finishing you MUST stop it and run `npm run qa` to completion.

## Preferred workflow
When making changes:

1) Make the smallest change that could fix the problem.
2) Run `npm run qa`.
3) If failures occur:
   - Fix the root cause (not the symptom).
   - Re-run `npm run qa`.
4) When green, summarize:
   - What you changed
   - Why it fixes the issue
   - What command(s) you ran and final status

## Running E2E correctly (Wrangler + Playwright)
E2E tests are executed via:

- `npm run test:e2e` (Playwright)

Important expectations:
- The test server should run in the `test` environment on localhost:
  - `npm run dev:test` runs Wrangler on port 8789 with `--env test`
- The Worker should expose a health endpoint used by Playwright webServer readiness checks:
  - `GET /healthz` should return 200

If the E2E suite flakes, prefer:
- increasing readiness robustness (healthz checks, timeouts),
- reducing live-reload interference,
- or making tests more deterministic.

Do not disable tests to “make it pass”.

## Linting / typechecking expectations
Before considering work complete, ensure QA is green.
If changes touch JS/TS or config, you may optionally run these earlier to catch issues faster:

- `npm run lint`
- `npm run typecheck`

(But the required gate remains `npm run qa`.)

## Secrets & safety (must follow)
Never print, commit, or exfiltrate secrets.

Do not add or commit any of these:
- `.dev.vars*`
- `.env*`
- Cloudflare tokens / account IDs / secret values
- Playwright traces or bulky artifacts unless explicitly requested

If you create local helper files for testing, ensure they are ignored by `.gitignore`.

## Communication style for completion
When you finish a task, include:

- A bullet list of key changes
- Any files modified
- The final command you ran: `npm run qa`
- The outcome: PASS

If you cannot run commands in the environment, you must say so explicitly and provide the exact commands the user should run locally.

## Do not do these
- Do not claim "all tests pass" unless `npm run qa` actually ran and exited 0.
- Do not use `qa:watch` as a finishing condition.
- Do not remove coverage, assertions, or security checks just to green the pipeline.

