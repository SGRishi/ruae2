from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import fitz  # PyMuPDF

from . import db as dbmod
from .segment import (
    build_question_id,
    clip_to_pdf_bbox,
    extract_text_for_clip,
    maths_crop_key,
    maths_pdf_key,
    paper_page_ranges,
    render_clip_png,
    segment_document,
    write_asset_manifest_line,
    build_thumb,
)
from .topics import classify_topic


@dataclass(frozen=True)
class SegmentConfig:
    dpi: int = 144
    top_margin_pt: float = 10.0
    bottom_margin_pt: float = 10.0
    output_dir: Path = Path("data/crops")
    asset_manifest: Path = Path("data/maths-assets.jsonl")
    force: bool = False


def _fetch_files(conn: sqlite3.Connection, *, year: int | None, paper: int | None, file_id: str | None, kind: str | None) -> list[sqlite3.Row]:
    where = []
    params = []

    if kind:
        where.append("type = ?")
        params.append(kind)
    if year is not None:
        where.append("year = ?")
        params.append(year)
    if paper is not None:
        where.append("paper_number = ?")
        params.append(paper)
    if file_id:
        where.append("id = ?")
        params.append(file_id)

    sql = "SELECT * FROM maths_files"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY year DESC, paper_number ASC, path ASC"

    return list(conn.execute(sql, params).fetchall())


def _group_files_by_year_paper(rows: list[sqlite3.Row]) -> dict[tuple[int, int], list[sqlite3.Row]]:
    grouped: dict[tuple[int, int], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        y = row["year"]
        p = row["paper_number"]
        if y is None or p is None:
            continue
        grouped[(int(y), int(p))].append(row)
    return grouped


def segment_question_bank(
    conn: sqlite3.Connection,
    pdf_root: Path,
    *,
    year: int | None = None,
    paper: int | None = None,
    file_id: str | None = None,
    config: SegmentConfig,
    run_id: str | None = None,
) -> None:
    pdf_root = pdf_root.resolve()
    cfg = config

    files = _fetch_files(conn, year=year, paper=paper, file_id=file_id, kind=None)
    grouped = _group_files_by_year_paper(files)

    for (y, p), items in sorted(grouped.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        past_papers = [r for r in items if r["type"] == "past_paper"]
        mark_schemes = [r for r in items if r["type"] == "mark_scheme"]
        datasheets = [r for r in items if r["type"] == "datasheet"]

        if datasheets:
            # Link the first datasheet found for this year/paper.
            ds_id = str(datasheets[0]["id"])
            dbmod.upsert_datasheet(conn, year=y, paper_number=p, file_id=ds_id)

        if not past_papers:
            if run_id:
                dbmod.append_pipeline_log(conn, run_id, f"SEGMENT skip year={y} paper={p}: no past_paper files")
            continue

        if run_id:
            dbmod.append_pipeline_log(conn, run_id, f"SEGMENT year={y} paper={p} past_papers={len(past_papers)} mark_schemes={len(mark_schemes)}")

        paper_file = past_papers[0]
        scheme_file = mark_schemes[0] if mark_schemes else None

        paper_path = pdf_root / str(paper_file["path"])
        if not paper_path.exists():
            raise FileNotFoundError(str(paper_path))

        # Ensure the PDF itself is in the asset manifest.
        write_asset_manifest_line(cfg.asset_manifest, key=maths_pdf_key(str(paper_file["id"])), local_path=paper_path, content_type="application/pdf")

        paper_doc = fitz.open(str(paper_path))
        try:
            paper_ranges = paper_page_ranges(paper_doc)
            page_start, page_end = paper_ranges.get(int(p), (0, int(paper_doc.page_count)))
            paper_segments = segment_document(
                paper_doc,
                top_margin=cfg.top_margin_pt,
                bottom_margin=cfg.bottom_margin_pt,
                page_start=int(page_start),
                page_end=int(page_end),
                bold_only=True,
                anchor_mode="paper",
            )
            if not paper_segments:
                # Some PDFs may not embed fonts with "Bold" in the name.
                paper_segments = segment_document(
                    paper_doc,
                    top_margin=cfg.top_margin_pt,
                    bottom_margin=cfg.bottom_margin_pt,
                    page_start=int(page_start),
                    page_end=int(page_end),
                    bold_only=False,
                    anchor_mode="paper",
                )
            by_q: dict[int, list] = defaultdict(list)
            for seg in paper_segments:
                by_q[int(seg.q_number)].append(seg)

            question_ids: dict[int, str] = {}
            for q_num, segs in sorted(by_q.items(), key=lambda kv: kv[0]):
                qid = build_question_id(y, p, q_num)
                question_ids[q_num] = qid

                # Ensure the question row exists before inserting crops (FK constraint).
                q_label = f"Question {q_num}"
                dbmod.upsert_question(
                    conn,
                    {
                        "id": qid,
                        "year": y,
                        "paper_number": p,
                        "q_number": q_num,
                        "q_label": q_label,
                        "topic": "",
                        "topic_confidence": 0.0,
                        "text_extracted": "",
                    },
                )

                # Render question crops.
                segs_sorted = sorted(segs, key=lambda s: (s.page_index, s.y0_top))
                text_parts: list[str] = []
                first_crop_path: Path | None = None
                first_bbox: tuple[float, float, float, float] | None = None
                question_crop_ids: list[str] = []

                for idx, seg in enumerate(segs_sorted, start=1):
                    page = paper_doc.load_page(seg.page_index)
                    page_w = float(page.rect.width)
                    page_h = float(page.rect.height)
                    clip = fitz.Rect(0.0, float(seg.y0_top), page_w, float(seg.y1_top))
                    bbox = clip_to_pdf_bbox(page_h, clip)

                    crop_name = f"q_{idx:02d}.png"
                    crop_key = maths_crop_key(y, p, qid, crop_name)
                    crop_path = cfg.output_dir / str(y) / str(p) / qid / crop_name
                    render_clip_png(page, clip, dpi=cfg.dpi, out_path=crop_path)
                    write_asset_manifest_line(cfg.asset_manifest, key=crop_key, local_path=crop_path, content_type="image/png")

                    crop_id = f"crop_{qid}_question_{idx:02d}"
                    question_crop_ids.append(crop_id)
                    wrote = dbmod.upsert_crop(
                        conn,
                        {
                            "id": crop_id,
                            "question_id": qid,
                            "kind": "question",
                            "file_id": str(paper_file["id"]),
                            "page_index": int(seg.page_index),
                            "x0": bbox.x0,
                            "y0": bbox.y0,
                            "x1": bbox.x1,
                            "y1": bbox.y1,
                            "render_dpi": int(cfg.dpi),
                            "storage_kind": "r2",
                            "storage_key": crop_key,
                            "status": "auto",
                        },
                        force=cfg.force,
                    )
                    if wrote and run_id:
                        dbmod.append_pipeline_log(conn, run_id, f"CROP q={qid} kind=question id={crop_id} key={crop_key}")

                    text_parts.append(extract_text_for_clip(page, clip))

                    if first_crop_path is None:
                        first_crop_path = crop_path
                        first_bbox = (bbox.x0, bbox.y0, bbox.x1, bbox.y1)

                if question_crop_ids:
                    dbmod.delete_auto_crops_not_in(conn, question_id=qid, kind="question", keep_ids=question_crop_ids)

                text_extracted = " ".join([t for t in text_parts if t]).strip()
                topic, conf = classify_topic(text_extracted)

                dbmod.upsert_question(
                    conn,
                    {
                        "id": qid,
                        "year": y,
                        "paper_number": p,
                        "q_number": q_num,
                        "q_label": q_label,
                        "topic": topic,
                        "topic_confidence": conf,
                        "text_extracted": text_extracted,
                    },
                )

                # Thumb crop from the first question crop.
                if first_crop_path and first_bbox:
                    thumb_name = "thumb.png"
                    thumb_key = maths_crop_key(y, p, qid, thumb_name)
                    thumb_path = cfg.output_dir / str(y) / str(p) / qid / thumb_name
                    build_thumb(first_crop_path, thumb_path)
                    write_asset_manifest_line(cfg.asset_manifest, key=thumb_key, local_path=thumb_path, content_type="image/png")

                    thumb_id = f"crop_{qid}_thumb"
                    wrote_thumb = dbmod.upsert_crop(
                        conn,
                        {
                            "id": thumb_id,
                            "question_id": qid,
                            "kind": "thumb",
                            "file_id": str(paper_file["id"]),
                            "page_index": int(segs_sorted[0].page_index),
                            "x0": float(first_bbox[0]),
                            "y0": float(first_bbox[1]),
                            "x1": float(first_bbox[2]),
                            "y1": float(first_bbox[3]),
                            "render_dpi": int(cfg.dpi),
                            "storage_kind": "r2",
                            "storage_key": thumb_key,
                            "status": "auto",
                        },
                        force=cfg.force,
                    )
                    if wrote_thumb and run_id:
                        dbmod.append_pipeline_log(conn, run_id, f"CROP q={qid} kind=thumb id={thumb_id} key={thumb_key}")

                    dbmod.delete_auto_crops_not_in(conn, question_id=qid, kind="thumb", keep_ids=[thumb_id])

        finally:
            paper_doc.close()

        if not scheme_file:
            conn.commit()
            continue

        scheme_path = pdf_root / str(scheme_file["path"])
        if not scheme_path.exists():
            raise FileNotFoundError(str(scheme_path))

        write_asset_manifest_line(cfg.asset_manifest, key=maths_pdf_key(str(scheme_file["id"])), local_path=scheme_path, content_type="application/pdf")

        scheme_doc = fitz.open(str(scheme_path))
        try:
            scheme_ranges = paper_page_ranges(scheme_doc)
            scheme_start, scheme_end = scheme_ranges.get(int(p), (0, int(scheme_doc.page_count)))
            scheme_segments = segment_document(
                scheme_doc,
                top_margin=cfg.top_margin_pt,
                bottom_margin=cfg.bottom_margin_pt,
                page_start=int(scheme_start),
                page_end=int(scheme_end),
                bold_only=True,
                anchor_mode="scheme",
            )
            if not scheme_segments:
                scheme_segments = segment_document(
                    scheme_doc,
                    top_margin=cfg.top_margin_pt,
                    bottom_margin=cfg.bottom_margin_pt,
                    page_start=int(scheme_start),
                    page_end=int(scheme_end),
                    bold_only=False,
                    anchor_mode="scheme",
                )
            by_q_ans: dict[int, list] = defaultdict(list)
            for seg in scheme_segments:
                by_q_ans[int(seg.q_number)].append(seg)

            for q_num, qid in question_ids.items():
                ans_segs = by_q_ans.get(int(q_num)) or []
                if not ans_segs:
                    continue
                ans_sorted = sorted(ans_segs, key=lambda s: (s.page_index, s.y0_top))
                answer_crop_ids: list[str] = []
                for idx, seg in enumerate(ans_sorted, start=1):
                    page = scheme_doc.load_page(seg.page_index)
                    page_w = float(page.rect.width)
                    page_h = float(page.rect.height)
                    clip = fitz.Rect(0.0, float(seg.y0_top), page_w, float(seg.y1_top))
                    bbox = clip_to_pdf_bbox(page_h, clip)

                    crop_name = f"a_{idx:02d}.png"
                    crop_key = maths_crop_key(y, p, qid, crop_name)
                    crop_path = cfg.output_dir / str(y) / str(p) / qid / crop_name
                    render_clip_png(page, clip, dpi=cfg.dpi, out_path=crop_path)
                    write_asset_manifest_line(cfg.asset_manifest, key=crop_key, local_path=crop_path, content_type="image/png")

                    crop_id = f"crop_{qid}_answer_{idx:02d}"
                    answer_crop_ids.append(crop_id)
                    wrote = dbmod.upsert_crop(
                        conn,
                        {
                            "id": crop_id,
                            "question_id": qid,
                            "kind": "answer",
                            "file_id": str(scheme_file["id"]),
                            "page_index": int(seg.page_index),
                            "x0": bbox.x0,
                            "y0": bbox.y0,
                            "x1": bbox.x1,
                            "y1": bbox.y1,
                            "render_dpi": int(cfg.dpi),
                            "storage_kind": "r2",
                            "storage_key": crop_key,
                            "status": "auto",
                        },
                        force=cfg.force,
                    )
                    if wrote and run_id:
                        dbmod.append_pipeline_log(conn, run_id, f"CROP q={qid} kind=answer id={crop_id} key={crop_key}")

                if answer_crop_ids:
                    dbmod.delete_auto_crops_not_in(conn, question_id=qid, kind="answer", keep_ids=answer_crop_ids)
        finally:
            scheme_doc.close()

        conn.commit()
