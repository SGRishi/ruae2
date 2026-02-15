from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import fitz  # PyMuPDF
from PIL import Image

from .topics import classify_topic
from .util import BBox, safe_key_part


_PAPER_RE = re.compile(r"\bpaper\s+([12])\b", re.IGNORECASE)
_SESSION_RE = re.compile(r"\b(MAY|AUGUST|OCTOBER|NOVEMBER|DECEMBER)\b", re.IGNORECASE)
_ANCHOR_RE = re.compile(r"^(\d{1,2})\.$")


@dataclass(frozen=True)
class FileMeta:
    id: str
    path: Path
    type: str
    year: int | None
    paper_number: int | None
    calculator_allowed: int | None
    session: str | None
    tokens: list[str]
    sha256: str
    page_count: int


@dataclass(frozen=True)
class Anchor:
    q_number: int
    y_top: float  # points, origin top-left


@dataclass(frozen=True)
class Segment:
    q_number: int
    page_index: int
    y0_top: float
    y1_top: float


def parse_paper_number(first_page_text: str) -> int | None:
    if not first_page_text:
        return None
    match = _PAPER_RE.search(first_page_text)
    if not match:
        return None
    value = int(match.group(1))
    return value if value in (1, 2) else None


def parse_session(first_page_text: str) -> str | None:
    match = _SESSION_RE.search(first_page_text or "")
    if not match:
        return None
    return match.group(1).title()


def detect_anchors(page_dict: dict) -> list[Anchor]:
    anchors: list[Anchor] = []
    for block in page_dict.get("blocks", []) or []:
        for line in block.get("lines", []) or []:
            for span in line.get("spans", []) or []:
                text = str(span.get("text", "")).strip()
                match = _ANCHOR_RE.match(text)
                if not match:
                    continue
                bbox = span.get("bbox")
                if not bbox or len(bbox) != 4:
                    continue
                x0, y0, _x1, _y1 = bbox
                size = float(span.get("size") or 0)
                if size < 10.0:
                    continue
                if x0 > 90.0:
                    continue
                q = int(match.group(1))
                if q < 1 or q > 40:
                    continue
                anchors.append(Anchor(q_number=q, y_top=float(y0)))

    anchors.sort(key=lambda a: a.y_top)

    # Compress consecutive duplicates (mark schemes sometimes repeat the question number per-row).
    compressed: list[Anchor] = []
    for a in anchors:
        if compressed and compressed[-1].q_number == a.q_number:
            continue
        compressed.append(a)
    return compressed


def segment_document(
    doc: fitz.Document,
    *,
    top_margin: float = 8.0,
    bottom_margin: float = 8.0,
    page_start: int = 0,
    page_end: int | None = None,
) -> list[Segment]:
    # Collect all candidate anchors in reading order.
    all_anchors: list[tuple[int, Anchor]] = []
    if page_end is None:
        page_end = doc.page_count
    page_start = max(0, int(page_start))
    page_end = max(page_start, min(int(page_end), doc.page_count))

    for page_index in range(page_start, page_end):
        page = doc.load_page(page_index)
        page_dict = page.get_text("dict")
        anchors = detect_anchors(page_dict)
        for a in anchors:
            all_anchors.append((page_index, a))

    all_anchors.sort(key=lambda t: (t[0], t[1].y_top))

    # Filter to a monotonic increasing sequence of question starts. This avoids
    # splitting on repeated question numbers inside marking tables.
    main: list[tuple[int, Anchor]] = []
    current = 0
    for page_index, anchor in all_anchors:
        q = int(anchor.q_number)
        if q <= current:
            continue
        if current == 0 and q != 1:
            # Most papers start at 1; ignore other numbers in headers/tables.
            continue
        if q == current + 1 or (0 < (q - current) <= 2):
            main.append((page_index, anchor))
            current = q

    if not main:
        return []

    segments: list[Segment] = []
    for idx, (start_page_idx, start_anchor) in enumerate(main):
        start_page = doc.load_page(start_page_idx)
        start_h = float(start_page.rect.height)
        start_y0 = max(0.0, float(start_anchor.y_top) - top_margin)

        if idx + 1 < len(main):
            end_page_idx, end_anchor = main[idx + 1]
            end_y = float(end_anchor.y_top)
        else:
            end_page_idx, end_anchor = None, None
            end_y = 0.0

        if end_page_idx is None:
            # Last question runs to the end of the document.
            segments.append(Segment(q_number=start_anchor.q_number, page_index=start_page_idx, y0_top=start_y0, y1_top=start_h))
            for pi in range(start_page_idx + 1, page_end):
                page = doc.load_page(pi)
                segments.append(Segment(q_number=start_anchor.q_number, page_index=pi, y0_top=0.0, y1_top=float(page.rect.height)))
            continue

        if end_page_idx == start_page_idx:
            # Next question starts on the same page.
            y1 = max(0.0, min(start_h, end_y - bottom_margin))
            if y1 > start_y0 + 10:
                segments.append(Segment(q_number=start_anchor.q_number, page_index=start_page_idx, y0_top=start_y0, y1_top=y1))
            continue

        # Start page segment to end of page.
        segments.append(Segment(q_number=start_anchor.q_number, page_index=start_page_idx, y0_top=start_y0, y1_top=start_h))

        # Full middle pages.
        for pi in range(start_page_idx + 1, int(end_page_idx)):
            page = doc.load_page(pi)
            segments.append(Segment(q_number=start_anchor.q_number, page_index=pi, y0_top=0.0, y1_top=float(page.rect.height)))

        # End page segment up to the next anchor.
        end_page = doc.load_page(int(end_page_idx))
        end_h = float(end_page.rect.height)
        y1 = max(0.0, min(end_h, float(end_anchor.y_top) - bottom_margin))
        if y1 > 30.0:
            segments.append(Segment(q_number=start_anchor.q_number, page_index=int(end_page_idx), y0_top=0.0, y1_top=y1))

    return segments


def clip_to_pdf_bbox(page_height_pt: float, clip: fitz.Rect) -> BBox:
    # clip is in PyMuPDF page coordinates (origin top-left, points).
    x0 = float(clip.x0)
    x1 = float(clip.x1)
    y0 = float(page_height_pt - clip.y1)  # lower
    y1 = float(page_height_pt - clip.y0)  # upper
    return BBox(x0=x0, y0=y0, x1=x1, y1=y1).normalized()


def render_clip_png(page: fitz.Page, clip: fitz.Rect, *, dpi: int, out_path: Path) -> None:
    scale = dpi / 72.0
    mat = fitz.Matrix(scale, scale)
    pix = page.get_pixmap(matrix=mat, clip=clip, alpha=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pix.save(str(out_path))


def build_thumb(in_path: Path, out_path: Path, *, width_px: int = 360) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(in_path) as img:
        w, h = img.size
        if w <= 0 or h <= 0:
            raise ValueError("Invalid image size.")
        if w <= width_px:
            img.save(out_path)
            return
        ratio = width_px / float(w)
        target = (width_px, max(1, int(h * ratio)))
        thumb = img.resize(target, Image.LANCZOS)
        thumb.save(out_path)


def maths_pdf_key(file_id: str) -> str:
    return f"maths/pdfs/{safe_key_part(file_id)}.pdf"


def maths_crop_key(year: int, paper_number: int, question_id: str, filename: str) -> str:
    qid = safe_key_part(question_id)
    return f"maths/crops/{year}/{paper_number}/{qid}/{filename}"


def build_question_id(year: int, paper_number: int, q_number: int) -> str:
    return f"q_{year}_{paper_number}_{q_number}"


def extract_text_for_clip(page: fitz.Page, clip: fitz.Rect) -> str:
    try:
        text = page.get_text("text", clip=clip) or ""
    except Exception:
        return ""
    cleaned = " ".join(text.split())
    return cleaned.strip()


def write_asset_manifest_line(manifest_path: Path, *, key: str, local_path: Path, content_type: str) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {"key": key, "path": str(local_path), "contentType": content_type},
                ensure_ascii=True,
            )
            + "\n"
        )
