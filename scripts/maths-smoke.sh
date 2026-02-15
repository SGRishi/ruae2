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

def add_question_page(doc: fitz.Document, *, title: str):
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 72), title, fontsize=14)
    # Q1
    page.insert_text((50, 150), "1.", fontsize=12)
    page.insert_text((80, 150), "Solve x + 1 = 2.", fontsize=12)
    # Q2
    page.insert_text((50, 240), "2.", fontsize=12)
    page.insert_text((80, 240), "Differentiate f(x) = x^2.", fontsize=12)

def make_combined_paper(path: Path):
    doc = fitz.open()
    add_question_page(doc, title="Mathematics Paper 1 (Non-calculator) 2025")
    # Paper 2 cover + questions (same PDF to exercise splitting logic).
    add_question_page(doc, title="Mathematics Paper 2 2025")
    doc.save(str(path))
    doc.close()

def add_mark_scheme_page(doc: fitz.Document, *, paper: int):
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 72), f"Mathematics Higher - Paper {paper} Marking Instructions 2025", fontsize=14)
    # Include a table-like header row so scheme segmentation can find the start.
    page.insert_text((60, 110), "Question", fontsize=12)
    page.insert_text((160, 110), "Generic scheme", fontsize=12)
    page.insert_text((320, 110), "Illustrative scheme", fontsize=12)
    page.insert_text((480, 110), "Max mark", fontsize=12)

    # Q1 row/anchor
    page.insert_text((50, 150), "1.", fontsize=12)

    # A notes section with numbered items that must NOT be treated as question anchors.
    page.insert_text((50, 190), "Notes:", fontsize=12)
    page.insert_text((50, 210), "4.", fontsize=12)
    page.insert_text((80, 210), "Do not accept", fontsize=12)

    # Q2 row/anchor placed below Notes to ensure we don't over-filter by Notes position.
    page.insert_text((50, 260), "2.", fontsize=12)

def make_combined_mark_scheme(path: Path):
    doc = fitz.open()
    add_mark_scheme_page(doc, paper=1)
    add_mark_scheme_page(doc, paper=2)
    doc.save(str(path))
    doc.close()

make_combined_paper(out / "sample_paper_2025.pdf")
make_combined_mark_scheme(out / "sample_mark_scheme_2025_marking.pdf")
PY

DB_PATH="${WORK_DIR}/maths.sqlite"
ASSETS_MANIFEST="${WORK_DIR}/assets.jsonl"
OUT_DIR="${WORK_DIR}/crops"

python -m maths ingest "${WORK_DIR}" --db "${DB_PATH}"
python -m maths segment --pdf-root "${WORK_DIR}" --db "${DB_PATH}" --year 2025 --output-dir "${OUT_DIR}" --asset-manifest "${ASSETS_MANIFEST}"

python - <<PY
import sqlite3
from pathlib import Path

db = Path("${DB_PATH}")
conn = sqlite3.connect(str(db))
q = conn.execute("SELECT COUNT(1) FROM maths_questions").fetchone()[0]
c = conn.execute("SELECT COUNT(1) FROM maths_crops").fetchone()[0]
p = conn.execute("SELECT COUNT(1) FROM maths_questions WHERE year = 2025 AND paper_number = 2").fetchone()[0]
print("questions", q)
print("crops", c)
assert q >= 4
assert c >= 4
assert p >= 2
PY

test -s "${ASSETS_MANIFEST}"
echo "Smoke test OK"
