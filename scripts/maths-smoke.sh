#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -d "${ROOT_DIR}/.venv" ]]; then
  echo "Missing .venv. Create it with:"
  echo "  python3 -m venv .venv"
  echo "  . .venv/bin/activate && pip install -r maths/requirements.txt"
  exit 1
fi

. "${ROOT_DIR}/.venv/bin/activate"

WORK_DIR="${ROOT_DIR}/tmp/maths-smoke"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

python - <<'PY'
from pathlib import Path
import fitz

out = Path("tmp/maths-smoke").resolve()
out.mkdir(parents=True, exist_ok=True)

def make_paper(path: Path, title: str):
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 80), title, fontsize=14)
    # Q1
    page.insert_text((50, 150), "1.", fontsize=12)
    page.insert_text((80, 150), "Solve x + 1 = 2.", fontsize=12)
    # Q2
    page.insert_text((50, 240), "2.", fontsize=12)
    page.insert_text((80, 240), "Differentiate f(x) = x^2.", fontsize=12)
    doc.save(str(path))
    doc.close()

make_paper(out / "sample_paper_2025.pdf", "Mathematics Paper 1 (Non-calculator) 2025")
make_paper(out / "sample_mark_scheme_2025_marking.pdf", "Mathematics Higher - Paper 1 Marking Instructions 2025")
PY

DB_PATH="${WORK_DIR}/maths.sqlite"
ASSETS_MANIFEST="${WORK_DIR}/assets.jsonl"
OUT_DIR="${WORK_DIR}/crops"

python -m maths ingest "${WORK_DIR}" --db "${DB_PATH}"
python -m maths segment --pdf-root "${WORK_DIR}" --db "${DB_PATH}" --year 2025 --paper 1 --output-dir "${OUT_DIR}" --asset-manifest "${ASSETS_MANIFEST}"

python - <<PY
import sqlite3
from pathlib import Path

db = Path("${DB_PATH}")
conn = sqlite3.connect(str(db))
q = conn.execute("SELECT COUNT(1) FROM maths_questions").fetchone()[0]
c = conn.execute("SELECT COUNT(1) FROM maths_crops").fetchone()[0]
print("questions", q)
print("crops", c)
assert q >= 2
assert c >= 2
PY

test -s "${ASSETS_MANIFEST}"
echo "Smoke test OK"

