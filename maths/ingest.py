from __future__ import annotations

import json
from pathlib import Path

import fitz  # PyMuPDF

from . import db as dbmod
from .filenames import parse_filename
from .segment import parse_paper_number, parse_session
from .util import sha256_hex


def _extract_first_page_text(pdf_path: Path) -> str:
    doc = fitz.open(str(pdf_path))
    try:
        if doc.page_count < 1:
            return ""
        page0 = doc.load_page(0)
        return page0.get_text("text") or ""
    finally:
        doc.close()


def ingest_folder(conn, folder: Path, *, run_id: str | None = None) -> list[str]:
    folder = folder.resolve()
    if not folder.exists():
        raise FileNotFoundError(str(folder))

    # Avoid ingesting build artifacts/test fixtures when the repo root is used as input.
    # If users want those files, they can point `maths ingest` at a more specific folder.
    ignored_dirs = {
        ".git",
        ".wrangler",
        ".venv",
        "data",
        "dist",
        "node_modules",
        "test-results",
        "tmp",
    }

    pdfs: list[Path] = []
    for p in folder.rglob("*.pdf"):
        if not p.is_file():
            continue
        try:
            rel_parts = p.relative_to(folder).parts
        except ValueError:
            rel_parts = p.parts
        if any(part in ignored_dirs for part in rel_parts):
            continue
        pdfs.append(p)
    pdfs.sort()
    ingested_ids: list[str] = []

    for pdf_path in pdfs:
        parsed = parse_filename(pdf_path)
        sha = sha256_hex(pdf_path)
        file_id = sha

        first_text = _extract_first_page_text(pdf_path)
        paper_number = parse_paper_number(first_text)
        session = parse_session(first_text)

        year = parsed.year
        if year is None:
            # Fallback: try to find a year token in the first page.
            for token in first_text.split():
                if token.isdigit() and len(token) == 4:
                    y = int(token)
                    if 1990 <= y <= 2100:
                        year = y
                        break

        calculator_allowed = None
        if paper_number == 1:
            calculator_allowed = 0
        elif paper_number == 2:
            calculator_allowed = 1

        doc = fitz.open(str(pdf_path))
        try:
            page_count = int(doc.page_count)
        finally:
            doc.close()

        tokens_json = json.dumps(parsed.tokens, ensure_ascii=True)
        rel_path = str(pdf_path.relative_to(folder))

        dbmod.upsert_file(
            conn,
            {
                "id": file_id,
                "path": rel_path,
                "type": parsed.type,
                "year": year,
                "paper_number": paper_number,
                "calculator_allowed": calculator_allowed,
                "session": session,
                "tokens_json": tokens_json,
                "sha256": sha,
                "page_count": page_count,
            },
        )

        if run_id:
            dbmod.append_pipeline_log(conn, run_id, f"INGEST file={rel_path} id={file_id} type={parsed.type} year={year} paper={paper_number}")

        # Datasheet linking is best-effort at ingest time.
        if parsed.type == "datasheet" and year and paper_number:
            dbmod.upsert_datasheet(conn, year=year, paper_number=paper_number, file_id=file_id)

        ingested_ids.append(file_id)

    conn.commit()
    return ingested_ids
