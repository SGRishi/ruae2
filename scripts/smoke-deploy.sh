#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-${BASE_URL:-https://rishisubjects.co.uk}}"
API_BASE="${2:-${API_BASE:-https://api.rishisubjects.co.uk}}"
ORIGIN="$(node -e "process.stdout.write(new URL(process.argv[1]).origin)" "$BASE_URL")"

tmp_dir="$(mktemp -d)"
home_body="${tmp_dir}/home.body"
health_body="${tmp_dir}/health.body"
me_body="${tmp_dir}/me.body"
cookie_jar="${tmp_dir}/cookies.txt"

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
  if ! rg -qi "ruae|higher english" "${home_body}"; then
    printf 'FAIL: homepage content check did not find expected RUAE text\n' >&2
    exit 1
  fi
else
  if ! grep -Eqi "ruae|higher english" "${home_body}"; then
    printf 'FAIL: homepage content check did not find expected RUAE text\n' >&2
    exit 1
  fi
fi
printf 'PASS: homepage reachable with expected content\n'

health_status="$(curl -sS -H "Origin: ${ORIGIN}" -o "${health_body}" -w '%{http_code}' "${API_BASE}/api/health")"
require_status "${health_status}" "200" "api health"
node -e '
const fs = require("fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!payload || payload.ok !== true || payload.service !== "ruae-api") {
  throw new Error("unexpected health payload");
}
' "${health_body}"
printf 'PASS: /api/health payload validated\n'

me_status="$(
  curl -sS -c "${cookie_jar}" -b "${cookie_jar}" \
    -H "Origin: ${ORIGIN}" \
    -o "${me_body}" -w '%{http_code}' \
    "${API_BASE}/api/auth/me"
)"
require_status "${me_status}" "200" "api auth me"
node -e '
const fs = require("fs");
const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!payload || payload.ok !== true || typeof payload.csrfToken !== "string" || !payload.csrfToken) {
  throw new Error("unexpected /api/auth/me payload");
}
' "${me_body}"
printf 'PASS: /api/auth/me payload validated\n'

printf 'Smoke test completed successfully.\n'
