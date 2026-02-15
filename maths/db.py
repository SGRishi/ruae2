from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PipelineRun:
    id: str
    started_at: str


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def ensure_schema(conn: sqlite3.Connection, repo_root: Path) -> None:
    schema_path = repo_root / "d1" / "schema.sql"
    sql = schema_path.read_text("utf-8")
    conn.executescript(sql)
    conn.commit()


def start_pipeline_run(conn: sqlite3.Connection, *, scope: str) -> PipelineRun:
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO maths_pipeline_runs (id, started_at, status, scope, log_text) VALUES (?, CURRENT_TIMESTAMP, 'running', ?, '')",
        (run_id, scope),
    )
    conn.commit()
    row = conn.execute("SELECT started_at FROM maths_pipeline_runs WHERE id = ?", (run_id,)).fetchone()
    started_at = str(row["started_at"] if row else "")
    return PipelineRun(id=run_id, started_at=started_at)


def append_pipeline_log(conn: sqlite3.Connection, run_id: str, message: str) -> None:
    conn.execute(
        "UPDATE maths_pipeline_runs SET log_text = coalesce(log_text,'') || ? WHERE id = ?",
        (f"{message.rstrip()}\n", run_id),
    )


def finish_pipeline_run(conn: sqlite3.Connection, run_id: str, *, status: str) -> None:
    conn.execute(
        "UPDATE maths_pipeline_runs SET finished_at = CURRENT_TIMESTAMP, status = ? WHERE id = ?",
        (status, run_id),
    )
    conn.commit()


def upsert_file(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO maths_files (id, path, type, year, paper_number, calculator_allowed, session, tokens_json, sha256, page_count)
        VALUES (:id, :path, :type, :year, :paper_number, :calculator_allowed, :session, :tokens_json, :sha256, :page_count)
        ON CONFLICT(id) DO UPDATE SET
          path=excluded.path,
          type=excluded.type,
          year=excluded.year,
          paper_number=excluded.paper_number,
          calculator_allowed=excluded.calculator_allowed,
          session=excluded.session,
          tokens_json=excluded.tokens_json,
          sha256=excluded.sha256,
          page_count=excluded.page_count
        """,
        row,
    )


def upsert_question(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO maths_questions (id, year, paper_number, q_number, q_label, topic, topic_confidence, text_extracted)
        VALUES (:id, :year, :paper_number, :q_number, :q_label, :topic, :topic_confidence, :text_extracted)
        ON CONFLICT(id) DO UPDATE SET
          year=excluded.year,
          paper_number=excluded.paper_number,
          q_number=excluded.q_number,
          q_label=excluded.q_label,
          topic=excluded.topic,
          topic_confidence=excluded.topic_confidence,
          text_extracted=excluded.text_extracted
        """,
        row,
    )


def get_crop_status(conn: sqlite3.Connection, crop_id: str) -> str | None:
    row = conn.execute("SELECT status FROM maths_crops WHERE id = ?", (crop_id,)).fetchone()
    if not row:
        return None
    return str(row["status"] or "")


def upsert_crop(conn: sqlite3.Connection, row: dict[str, Any], *, force: bool) -> bool:
    existing_status = get_crop_status(conn, str(row["id"]))
    if existing_status == "reviewed" and not force:
        return False

    conn.execute(
        """
        INSERT INTO maths_crops (id, question_id, kind, file_id, page_index, x0, y0, x1, y1, render_dpi, storage_kind, storage_key, status)
        VALUES (:id, :question_id, :kind, :file_id, :page_index, :x0, :y0, :x1, :y1, :render_dpi, :storage_kind, :storage_key, :status)
        ON CONFLICT(id) DO UPDATE SET
          question_id=excluded.question_id,
          kind=excluded.kind,
          file_id=excluded.file_id,
          page_index=excluded.page_index,
          x0=excluded.x0,
          y0=excluded.y0,
          x1=excluded.x1,
          y1=excluded.y1,
          render_dpi=excluded.render_dpi,
          storage_kind=excluded.storage_kind,
          storage_key=excluded.storage_key,
          status=excluded.status,
          updated_at=CURRENT_TIMESTAMP
        """,
        row,
    )
    return True


def upsert_datasheet(conn: sqlite3.Connection, *, year: int, paper_number: int, file_id: str) -> None:
    conn.execute(
        """
        INSERT INTO maths_datasheets (id, year, paper_number, file_id)
        VALUES (:id, :year, :paper_number, :file_id)
        ON CONFLICT(year, paper_number) DO UPDATE SET
          file_id=excluded.file_id
        """,
        {
            "id": f"ds_{year}_{paper_number}",
            "year": year,
            "paper_number": paper_number,
            "file_id": file_id,
        },
    )

