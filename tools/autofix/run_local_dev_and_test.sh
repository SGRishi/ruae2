#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_FILE="$ROOT_DIR/tools/autofix/last_local.log"
DEV_LOG_FILE="$ROOT_DIR/tools/autofix/dev_server.log"

LOCAL_URL="${LOCAL_URL:-http://127.0.0.1:3000/countdown}"

origin_from_url() {
  local url="$1"
  printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*$#\1#'
}

path_from_url() {
  local url="$1"
  local path
  path="$(printf '%s' "$url" | sed -E 's#^https?://[^/]+##')"
  if [[ -z "$path" ]]; then
    path='/'
  fi
  printf '%s' "$path"
}

infer_dev_cmd() {
  if node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));process.exit(pkg.scripts && pkg.scripts.preview ? 0 : 1);"; then
    printf '%s' 'npm run preview'
    return 0
  fi
  if node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));process.exit(pkg.scripts && pkg.scripts['dev:test'] ? 0 : 1);"; then
    printf '%s' 'npm run dev:test'
    return 0
  fi
  if node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));process.exit(pkg.scripts && pkg.scripts.dev ? 0 : 1);"; then
    printf '%s' 'npm run dev'
    return 0
  fi
  if node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));process.exit(pkg.scripts && pkg.scripts.start ? 0 : 1);"; then
    printf '%s' 'npm run start'
    return 0
  fi
  return 1
}

BASE_URL="${BASE_URL:-$(origin_from_url "$LOCAL_URL")}"
SMOKE_PATH="${SMOKE_PATH:-$(path_from_url "$LOCAL_URL")}"
HEALTH_URL="${HEALTH_URL:-${BASE_URL}/healthz}"
DEV_CMD="${DEV_CMD:-}"

if [[ -z "$DEV_CMD" ]]; then
  if ! DEV_CMD="$(infer_dev_cmd)"; then
    echo "Unable to infer DEV_CMD. Set DEV_CMD and LOCAL_URL explicitly." >&2
    exit 1
  fi
fi

cd "$ROOT_DIR"

cleanup() {
  if [[ -n "${DEV_PID:-}" ]] && kill -0 "$DEV_PID" >/dev/null 2>&1; then
    kill "$DEV_PID" >/dev/null 2>&1 || true
    wait "$DEV_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

: > "$DEV_LOG_FILE"

echo "[local_test] Starting dev server with: $DEV_CMD" | tee "$LOG_FILE"
bash -lc "$DEV_CMD" >"$DEV_LOG_FILE" 2>&1 &
DEV_PID=$!

ready=0
for _ in $(seq 1 90); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "[local_test] Dev server did not become healthy at $HEALTH_URL" | tee -a "$LOG_FILE"
  tail -n 80 "$DEV_LOG_FILE" | tee -a "$LOG_FILE"
  exit 1
fi

{
  echo "[local_test] LOCAL_URL=$LOCAL_URL"
  echo "[local_test] BASE_URL=$BASE_URL"
  echo "[local_test] SMOKE_PATH=$SMOKE_PATH"
  BASE_URL="$BASE_URL" SMOKE_PATH="$SMOKE_PATH" npx playwright test --workers=1
} | tee -a "$LOG_FILE"

exit "${PIPESTATUS[0]}"
