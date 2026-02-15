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
_PAPER_ANCHOR_RE = re.compile(r"^(\d{1,2})\.$")
# Marking instructions vary across years: "9", "9.", "11(a).", "13 (b)(i)", "14.(c)".
# Keep this strict (no trailing words) to avoid matching note text like "5. An incorrect ...".
_SCHEME_ANCHOR_RE = re.compile(r"^(\d{1,2})\s*\.?\s*(?:\([a-z0-9]+\)\s*)*(?:\.)?$", re.IGNORECASE)

def scheme_header_bottom_y(page_dict: dict) -> float | None:
    """Return the bottom y (top-origin) of the scheme table header row, when present.

    Mark schemes typically repeat a header row ("Question", "Generic scheme", etc.) at the
    top of each page. We use this to avoid generating crops that contain only the header.
    """
    best: float | None = None

    for block in page_dict.get("blocks", []) or []:
        for line in block.get("lines", []) or []:
            spans = line.get("spans", []) or []
            if not spans:
                continue

            has_question = False
            top = 1e9
            bottom = -1.0

            for span in spans:
                text = str(span.get("text", "")).strip().lower()
                if text == "question":
                    has_question = True

                bbox = span.get("bbox")
                if not bbox or len(bbox) != 4:
                    continue
                y0 = float(bbox[1])
                y1 = float(bbox[3])
                top = min(top, y0)
                bottom = max(bottom, y1)

            if not has_question:
                continue
            if bottom < 0:
                continue
            if top >= 250.0:
                continue
            if best is None or bottom > best:
                best = bottom

    return best


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

def paper_page_ranges(doc: fitz.Document) -> dict[int, tuple[int, int]]:
    """Return page ranges (start, end) for each paper number detected in the PDF.

    Many SQA PDFs bundle Paper 1 and Paper 2 into a single file. We detect the
    first page where each paper appears and compute contiguous ranges.
    """
    starts: dict[int, int] = {}
    for pi in range(int(doc.page_count)):
        try:
            text = doc.load_page(pi).get_text("text") or ""
        except Exception:
            text = ""
        p = parse_paper_number(text)
        if p in (1, 2) and int(p) not in starts:
            starts[int(p)] = int(pi)
            if len(starts) >= 2:
                # In practice papers are contiguous and we only expect 1 or 2.
                # Early exit keeps ingest/segmentation snappy on larger PDFs.
                break

    if not starts:
        return {}

    ordered = sorted(starts.items(), key=lambda kv: kv[1])
    ranges: dict[int, tuple[int, int]] = {}
    for idx, (paper, start) in enumerate(ordered):
        end = ordered[idx + 1][1] if idx + 1 < len(ordered) else int(doc.page_count)
        ranges[int(paper)] = (int(start), int(end))
    return ranges


def detect_anchors(page_dict: dict, *, bold_only: bool = False, anchor_mode: str = "paper") -> list[Anchor]:
    anchors: list[Anchor] = []
    if anchor_mode not in ("paper", "scheme"):
        raise ValueError(f"Unknown anchor_mode={anchor_mode!r}")

    for block in page_dict.get("blocks", []) or []:
        block_has_notes = False
        if anchor_mode == "scheme":
            for line in block.get("lines", []) or []:
                for span in line.get("spans", []) or []:
                    if str(span.get("text", "")).strip().lower() == "notes:":
                        block_has_notes = True
                        break
                if block_has_notes:
                    break
            if block_has_notes:
                # Notes blocks often contain numbered items (e.g. "4.", "5.") that are not
                # question starts. Skip the entire block to avoid tiny bogus crops.
                continue

        for line in block.get("lines", []) or []:
            spans = line.get("spans", []) or []
            if not spans:
                continue

            cand_spans: list[dict] = []
            if anchor_mode == "paper":
                # Papers are safe to scan span-by-span; question numbers are usually isolated spans.
                cand_spans = list(spans)
            else:
                # Marking instructions contain lots of maths. Only consider the left-most span
                # per line; digits inside equations are rarely left-most.
                left = None
                left_x0 = 1e9
                for span in spans:
                    bbox = span.get("bbox")
                    if not bbox or len(bbox) != 4:
                        continue
                    x0 = float(bbox[0])
                    if x0 < left_x0:
                        left = span
                        left_x0 = x0
                if left is not None:
                    cand_spans = [left]

            for span in cand_spans:
                text = str(span.get("text", "")).strip()
                if not text:
                    continue

                match = _PAPER_ANCHOR_RE.match(text) if anchor_mode == "paper" else _SCHEME_ANCHOR_RE.match(text)
                if not match:
                    continue

                font = str(span.get("font") or "")
                if bold_only and "bold" not in font.lower():
                    continue

                # Extra safety: digit-only anchors are noisy in schemes; require bold even when
                # bold_only=False (fallback mode).
                if anchor_mode == "scheme" and text.isdigit() and "bold" not in font.lower():
                    continue

                if anchor_mode == "scheme":
                    # Reject note-item numbering like "6. Where candidates..." by ensuring the
                    # line contains only the anchor token plus optional part tokens (e.g. "(a)").
                    other = []
                    for sp in spans:
                        t = str(sp.get("text", "")).strip()
                        if not t:
                            continue
                        if t == text:
                            continue
                        # Allow pure part tokens beside the number.
                        if re.fullmatch(r"\([a-z0-9]+\)", t, flags=re.IGNORECASE):
                            continue
                        other.append(t)
                    if other:
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
    bold_only: bool = False,
    anchor_mode: str = "paper",
) -> list[Segment]:
    # Collect all candidate anchors in reading order.
    all_anchors: list[tuple[int, Anchor]] = []
    if page_end is None:
        page_end = doc.page_count
    page_start = max(0, int(page_start))
    page_end = max(page_start, min(int(page_end), doc.page_count))

    if anchor_mode == "scheme":
        # Marking instructions often include intro pages (general rules, examples, etc.) before
        # the question-by-question tables. Anchors on those pages are not question numbers.
        # Find the first page that contains the table header "Question" near the top.
        for pi in range(page_start, page_end):
            try:
                page_dict = doc.load_page(pi).get_text("dict")
            except Exception:
                continue
            found = False
            for block in page_dict.get("blocks", []) or []:
                for line in block.get("lines", []) or []:
                    for span in line.get("spans", []) or []:
                        text = str(span.get("text", "")).strip()
                        if text.lower() != "question":
                            continue
                        bbox = span.get("bbox")
                        if bbox and len(bbox) == 4:
                            _x0, y0, _x1, _y1 = bbox
                            if float(y0) < 200.0:
                                found = True
                                break
                    if found:
                        break
                if found:
                    break
            if found:
                page_start = int(pi)
                break

    scheme_header_bottom_by_page: dict[int, float] = {}
    for page_index in range(page_start, page_end):
        page = doc.load_page(page_index)
        page_dict = page.get_text("dict")
        if anchor_mode == "scheme":
            bottom = scheme_header_bottom_y(page_dict)
            if bottom is not None:
                scheme_header_bottom_by_page[int(page_index)] = float(bottom)
        anchors = detect_anchors(page_dict, bold_only=bold_only, anchor_mode=anchor_mode)
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

    def scheme_content_y0(page_index: int) -> float:
        if anchor_mode != "scheme":
            return 0.0
        bottom = scheme_header_bottom_by_page.get(int(page_index))
        if bottom is None:
            return 0.0
        # Pad to clear the header row + border.
        return max(0.0, float(bottom) + 6.0)

    for idx, (start_page_idx, start_anchor) in enumerate(main):
        start_page = doc.load_page(start_page_idx)
        start_h = float(start_page.rect.height)
        start_y0 = max(0.0, float(start_anchor.y_top) - top_margin)
        start_y0 = max(start_y0, scheme_content_y0(start_page_idx))

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
                y0 = scheme_content_y0(pi)
                segments.append(Segment(q_number=start_anchor.q_number, page_index=pi, y0_top=y0, y1_top=float(page.rect.height)))
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
            y0 = scheme_content_y0(pi)
            segments.append(Segment(q_number=start_anchor.q_number, page_index=pi, y0_top=y0, y1_top=float(page.rect.height)))

        # End page segment up to the next anchor.
        end_page = doc.load_page(int(end_page_idx))
        end_h = float(end_page.rect.height)
        y1 = max(0.0, min(end_h, float(end_anchor.y_top) - bottom_margin))
        y0 = scheme_content_y0(int(end_page_idx))
        if y1 > y0 + 30.0:
            segments.append(Segment(q_number=start_anchor.q_number, page_index=int(end_page_idx), y0_top=y0, y1_top=y1))

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
