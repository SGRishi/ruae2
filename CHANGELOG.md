# Changelog

## 2026-03-07

- Removed legacy non-countdown website assets and legacy content files.
- Simplified backend to countdown-only API surface:
  - `/api/health`
  - `/api/time`
  - `/api/resolve-date`
  - `/api/resolve-event-date`
  - `/api/countdown/timer`
  - `/api/countdown/access`
- Reduced D1 schema to countdown timer storage only.
- Updated smoke/deploy and docs to countdown-only scope.
