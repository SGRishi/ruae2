from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


_YEAR_RE = re.compile(r"(19|20)\d{2}")


@dataclass(frozen=True)
class ParsedName:
    year: int | None
    type: str  # past_paper | mark_scheme | datasheet
    tokens: list[str]


def tokenize_filename(path: Path) -> list[str]:
    name = path.stem.lower()
    parts = re.split(r"[^a-z0-9]+", name)
    return [p for p in parts if p]


def parse_year_from_filename(path: Path) -> int | None:
    match = _YEAR_RE.search(path.name)
    if not match:
        return None
    year = int(match.group(0))
    if year < 1990 or year > 2100:
        return None
    return year


def parse_type_from_filename(path: Path) -> str:
    lower = path.name.lower()
    tokens = set(tokenize_filename(path))

    datasheet_tokens = {
        "datasheet",
        "data",
        "sheet",
        "formulasheet",
        "formula",
        "relationshipsheet",
        "relationship",
        "infosheet",
        "info",
    }

    if (
        any(t in tokens for t in datasheet_tokens)
        or "datasheet" in lower
        or "data sheet" in lower
        or "formula sheet" in lower
        or "relationship sheet" in lower
        or "info sheet" in lower
    ):
        return "datasheet"

    # Common marking-scheme tokens. Avoid bare "ms" because it appears inside "maths".
    if (
        "msch" in tokens
        or "mark" in tokens
        or "marking" in tokens
        or "scheme" in tokens
        or "msch" in lower
        or "marking" in lower
        or "mark" in lower
    ):
        return "mark_scheme"

    return "past_paper"


def parse_filename(path: Path) -> ParsedName:
    tokens = tokenize_filename(path)
    return ParsedName(
        year=parse_year_from_filename(path),
        type=parse_type_from_filename(path),
        tokens=tokens,
    )
