#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCAL_LOG="$ROOT_DIR/tools/autofix/last_local.log"

cd "$ROOT_DIR"

if ! bash tools/autofix/run_local_dev_and_test.sh; then
  echo "[autofix_local] Local tests failed. Review $LOCAL_LOG, apply one fix, and rerun." >&2
  exit 1
fi

git add -A

SECRET_MATCHES="$(git diff --cached --name-only | rg '^(\.dev\.vars.*|\.env.*)$' || true)"
if [[ -n "$SECRET_MATCHES" ]]; then
  echo "[autofix_local] Refusing to commit secret/env files:" >&2
  echo "$SECRET_MATCHES" >&2
  exit 1
fi

if ! git diff --cached --quiet; then
  git commit -m "Autofix: make E2E pass"
  git push
else
  echo "[autofix_local] No changes to commit."
fi

if ! bash tools/autofix/smoke_live.sh; then
  echo "[autofix_local] Live smoke failed. This is read-only; no production auto-fix was attempted." >&2
  exit 1
fi

echo "[autofix_local] Completed local pass + push + live smoke."
