#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_FILE="$ROOT_DIR/tools/autofix/last_live.log"

LIVE_URL="${LIVE_URL:-https://rishisubjects.co.uk/countdown}"

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

BASE_URL="${BASE_URL:-$(origin_from_url "$LIVE_URL")}"
SMOKE_PATH="${SMOKE_PATH:-$(path_from_url "$LIVE_URL")}"

cd "$ROOT_DIR"

{
  echo "[smoke_live] LIVE_URL=$LIVE_URL"
  echo "[smoke_live] BASE_URL=$BASE_URL"
  echo "[smoke_live] SMOKE_PATH=$SMOKE_PATH"
  BASE_URL="$BASE_URL" SMOKE_PATH="$SMOKE_PATH" npx playwright test tests/e2e/live-smoke.spec.ts --workers=1 --retries=0
} | tee "$LOG_FILE"

exit "${PIPESTATUS[0]}"
