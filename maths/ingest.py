from __future__ import annotations

import json
from pathlib import Path

import fitz  # PyMuPDF

from . import db as dbmod
from .filenames import parse_filename
from .segment import paper_page_ranges, parse_paper_number, parse_session
from .util import sha256_hex


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
        base_id = sha

        doc = fitz.open(str(pdf_path))
        try:
            page_count = int(doc.page_count)
            page0_text = (doc.load_page(0).get_text("text") or "") if page_count else ""
            paper0 = parse_paper_number(page0_text)
            ranges = paper_page_ranges(doc)
            # If we can't detect papers, fall back to whatever the first page says.
            if not ranges and paper0 in (1, 2):
                ranges = {int(paper0): (0, page_count)}

            # Choose a year using filename first, then fallback to the first cover page we have.
            year = parsed.year
            if year is None:
                cover_text = page0_text
                for token in cover_text.split():
                    if token.isdigit() and len(token) == 4:
                        y = int(token)
                        if 1990 <= y <= 2100:
                            year = y
                            break

            rel_path = str(pdf_path.relative_to(folder))
            tokens_json = json.dumps(parsed.tokens, ensure_ascii=True)

            if not ranges:
                session = parse_session(page0_text)
                calculator_allowed = None
                if paper0 == 1:
                    calculator_allowed = 0
                elif paper0 == 2:
                    calculator_allowed = 1

                dbmod.upsert_file(
                    conn,
                    {
                        "id": base_id,
                        "path": rel_path,
                        "type": parsed.type,
                        "year": year,
                        "paper_number": paper0,
                        "calculator_allowed": calculator_allowed,
                        "session": session,
                        "tokens_json": tokens_json,
                        "sha256": sha,
                        "page_count": page_count,
                    },
                )
                if run_id:
                    dbmod.append_pipeline_log(
                        conn,
                        run_id,
                        f"INGEST file={rel_path} id={base_id} type={parsed.type} year={year} paper={paper0}",
                    )
                if parsed.type == "datasheet" and year and paper0 in (1, 2):
                    dbmod.upsert_datasheet(conn, year=int(year), paper_number=int(paper0), file_id=base_id)
                ingested_ids.append(base_id)
                continue

            # Insert one row per detected paper number (most PDFs bundle Paper 1 + 2).
            for paper_number, (start, _end) in sorted(ranges.items(), key=lambda kv: kv[0]):
                cover_text = (doc.load_page(int(start)).get_text("text") or "") if page_count else ""
                session = parse_session(cover_text or page0_text)

                calculator_allowed = None
                if int(paper_number) == 1:
                    calculator_allowed = 0
                elif int(paper_number) == 2:
                    calculator_allowed = 1

                file_id = base_id if (paper0 in (1, 2) and int(paper_number) == int(paper0)) else f"{base_id}_p{int(paper_number)}"

                dbmod.upsert_file(
                    conn,
                    {
                        "id": file_id,
                        "path": rel_path,
                        "type": parsed.type,
                        "year": year,
                        "paper_number": int(paper_number),
                        "calculator_allowed": calculator_allowed,
                        "session": session,
                        "tokens_json": tokens_json,
                        "sha256": sha,
                        "page_count": page_count,
                    },
                )

                if run_id:
                    dbmod.append_pipeline_log(
                        conn,
                        run_id,
                        f"INGEST file={rel_path} id={file_id} type={parsed.type} year={year} paper={paper_number}",
                    )

                # Datasheet linking is best-effort at ingest time.
                if parsed.type == "datasheet" and year and paper_number:
                    dbmod.upsert_datasheet(conn, year=int(year), paper_number=int(paper_number), file_id=file_id)

                ingested_ids.append(file_id)
        finally:
            doc.close()

    conn.commit()
    return ingested_ids
