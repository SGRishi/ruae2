from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_SAFE_PART_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_key_part(value: str, *, max_len: int = 120) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    cleaned = _SAFE_PART_RE.sub("_", raw)
    return cleaned[:max_len]


@dataclass(frozen=True)
class BBox:
    # PDF coordinate space (points), origin bottom-left.
    x0: float
    y0: float
    x1: float
    y1: float

    def normalized(self) -> "BBox":
        return BBox(
            x0=min(self.x0, self.x1),
            y0=min(self.y0, self.y1),
            x1=max(self.x0, self.x1),
            y1=max(self.y0, self.y1),
        )

