#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-${BASE_URL:-https://rishisubjects.co.uk}}"
API_BASE="${2:-${API_BASE:-https://api.rishisubjects.co.uk}}"
ORIGIN="$(node -e "process.stdout.write(new URL(process.argv[1]).origin)" "$BASE_URL")"

tmp_dir="$(mktemp -d)"
home_body="${tmp_dir}/home.body"
health_body="${tmp_dir}/health.body"
time_body="${tmp_dir}/time.body"
legacy_body="${tmp_dir}/legacy.body"

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

require_status() {
  local actual="$1"
  local expected="$2"
  local name="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'FAIL: %s expected status %s, got %s\n' "${name}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

printf 'Smoke target: BASE_URL=%s API_BASE=%s\n' "${BASE_URL}" "${API_BASE}"

home_status="$(curl -sS -o "${home_body}" -w '%{http_code}' "${BASE_URL}/")"
require_status "${home_status}" "200" "homepage"
if command -v rg >/dev/null 2>&1; then
  rg -qi 'countdown' "${home_body}" || {
    printf 'FAIL: homepage does not contain countdown UI\n' >&2
    exit 1
  }
else
  grep -Eqi 'countdown' "${home_body}" || {
    printf 'FAIL: homepage does not contain countdown UI\n' >&2
    exit 1
  }
fi
printf 'PASS: homepage countdown UI reachable\n'

health_status="$(curl -sS -H "Origin: ${ORIGIN}" -o "${health_body}" -w '%{http_code}' "${API_BASE}/api/health")"
require_status "${health_status}" "200" "api health"
node -e '
const fs = require("fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!payload || payload.ok !== true || payload.service !== "countdown-api") {
  throw new Error("unexpected health payload");
}
' "${health_body}"
printf 'PASS: /api/health payload validated\n'

time_status="$(curl -sS -H "Origin: ${ORIGIN}" -o "${time_body}" -w '%{http_code}' "${API_BASE}/api/time")"
require_status "${time_status}" "200" "api time"
node -e '
const fs = require("fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!payload || payload.ok !== true || typeof payload.nowMs !== "number") {
  throw new Error("unexpected /api/time payload");
}
' "${time_body}"
printf 'PASS: /api/time payload validated\n'

legacy_status="$(curl -sS -o "${legacy_body}" -w '%{http_code}' "${BASE_URL}/legacy-route")"
require_status "${legacy_status}" "404" "legacy route"
printf 'PASS: legacy routes disabled\n'

printf 'Smoke test completed successfully.\n'
