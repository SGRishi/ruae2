# Changelog

## 2026-02-14

- Added CI workflow `.github/workflows/ci.yml` running install, lint, typecheck, format check, tests, and build.
- Added smoke workflow `.github/workflows/smoke-deploy.yml` and script `scripts/smoke-deploy.sh` for deployed endpoint verification.
- Added ESLint, Prettier, and strict scoped TypeScript typecheck configuration.
- Expanded automated tests:
  - e2e happy path: `tests/e2e/auth-happy-path.test.mjs`
  - integration edge/security coverage: `tests/integration/auth-edge.test.mjs`
- Updated documentation:
  - `README.md` setup/env/test/deploy instructions
  - `DEPLOY.md` CLI deploy + smoke verification
  - `SECURITY.md` least-privilege token scope requirements and verified status
