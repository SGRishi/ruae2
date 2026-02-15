from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from . import db as dbmod
from .ingest import ingest_folder
from .pipeline import SegmentConfig, segment_question_bank

try:
    import tomllib  # py>=3.11
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_db_path() -> Path:
    return repo_root() / "data" / "maths-local.sqlite"


def run(cmd: list[str], *, cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd or repo_root()))
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}")


def load_toml(path: Path) -> dict:
    if tomllib is None:
        raise RuntimeError("tomllib is required (Python 3.11+).")
    return tomllib.loads(path.read_text("utf-8"))


def cloudflare_bearer_token() -> str:
    # Prefer explicit API token, otherwise fall back to wrangler's OAuth token.
    token = (os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN") or "").strip()
    if token:
        return token

    cfg_path = Path.home() / ".config" / ".wrangler" / "config" / "default.toml"
    if not cfg_path.exists():
        raise RuntimeError("Missing Cloudflare credentials. Run `npx wrangler login` or set CLOUDFLARE_API_TOKEN.")

    cfg = load_toml(cfg_path)
    oauth = str(cfg.get("oauth_token") or "").strip()
    if not oauth:
        raise RuntimeError("Wrangler OAuth token missing. Run `npx wrangler login` again.")
    return oauth


def cloudflare_account_and_kv_namespace_id(binding: str) -> tuple[str, str]:
    wrangler_path = repo_root() / "wrangler.toml"
    if not wrangler_path.exists():
        raise FileNotFoundError(str(wrangler_path))

    cfg = load_toml(wrangler_path)
    account_id = str(cfg.get("account_id") or "").strip()
    if not account_id:
        raise RuntimeError("wrangler.toml is missing account_id.")

    namespaces = cfg.get("kv_namespaces") or []
    for entry in namespaces:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("binding") or "").strip() != binding:
            continue
        ns_id = str(entry.get("id") or "").strip()
        if not ns_id:
            raise RuntimeError(f"wrangler.toml kv_namespaces entry for {binding} is missing id.")
        return account_id, ns_id

    raise RuntimeError(f"KV binding {binding} not found in wrangler.toml.")


def cloudflare_api_json(method: str, url: str, *, token: str, payload: object | None = None, timeout: int = 300) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise RuntimeError(f"Cloudflare API error {exc.code} {exc.reason}: {body}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cloudflare API request failed: {exc}") from None

    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise RuntimeError(f"Cloudflare API returned non-JSON response: {raw[:200]!r}") from None


def cloudflare_kv_bulk_put(*, account_id: str, namespace_id: str, token: str, items: list[dict]) -> None:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{namespace_id}/bulk"
    resp = cloudflare_api_json("PUT", url, token=token, payload=items)
    if not resp.get("success"):
        errors = resp.get("errors") or []
        raise RuntimeError(f"KV bulk put failed: {errors}")
    result = resp.get("result") or {}
    unsuccessful = result.get("unsuccessful_keys") or []
    if unsuccessful:
        raise RuntimeError(f"KV bulk put had unsuccessful keys: {unsuccessful}")

def split_sql_statements(script: str) -> list[str]:
    """Best-effort SQL splitter that avoids breaking on semicolons inside strings/comments."""
    out: list[str] = []
    buf: list[str] = []
    i = 0
    in_single = False
    in_double = False
    in_line_comment = False
    in_block_comment = False

    while i < len(script):
        ch = script[i]
        nxt = script[i + 1] if i + 1 < len(script) else ""

        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if not in_single and not in_double:
            if ch == "-" and nxt == "-":
                buf.append(ch)
                buf.append(nxt)
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                buf.append(ch)
                buf.append(nxt)
                in_block_comment = True
                i += 2
                continue

        if in_single:
            buf.append(ch)
            if ch == "'" and nxt == "'":
                buf.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue

        if in_double:
            buf.append(ch)
            if ch == '"' and nxt == '"':
                buf.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue

        if ch == "'":
            buf.append(ch)
            in_single = True
            i += 1
            continue
        if ch == '"':
            buf.append(ch)
            in_double = True
            i += 1
            continue

        if ch == ";":
            buf.append(ch)
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def execute_remote_d1_script(database_name: str, script: str) -> None:
    """Execute a SQL script on remote D1 without using --file (avoids /import auth issues)."""
    statements = split_sql_statements(script)
    if not statements:
        return

    # Keep chunks well under typical argument/API limits.
    max_chunk_chars = 40_000
    chunk: list[str] = []
    chunk_len = 0

    def flush() -> None:
        nonlocal chunk, chunk_len
        if not chunk:
            return
        sql = "\n".join(chunk)
        proc = subprocess.run(
            ["npx", "wrangler", "d1", "execute", database_name, "--remote", "--command", sql],
            cwd=str(repo_root()),
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or "") + (proc.stdout or "")
            raise RuntimeError(f"D1 execute failed:\n{stderr}")
        chunk = []
        chunk_len = 0

    for stmt in statements:
        # Ensure each statement is terminated; makes logs/errors easier to understand.
        normalized = stmt.strip()
        if not normalized:
            continue
        if not normalized.endswith(";"):
            normalized += ";"

        if chunk_len and chunk_len + len(normalized) + 1 > max_chunk_chars:
            flush()

        chunk.append(normalized)
        chunk_len += len(normalized) + 1

    flush()


def sql_literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Avoid blobs in exports.
        raise TypeError("BLOB values are not supported in SQL exports.")
    s = str(value)
    return "'" + s.replace("'", "''") + "'"


def export_maths_sql(conn, out_path: Path) -> None:
    tables = [
        "maths_files",
        "maths_questions",
        "maths_crops",
        "maths_datasheets",
        "maths_pipeline_runs",
    ]

    lines: list[str] = []
    lines.append("PRAGMA foreign_keys=ON;")
    # Avoid clobbering production review edits:
    # - Wipe only auto crops (including legacy rows where status is NULL).
    # - Re-insert auto crops from the pipeline; reviewed crops are kept as-is.
    lines.append("DELETE FROM maths_crops WHERE status IS NULL OR status = 'auto';")

    for table in tables:
        rows = list(conn.execute(f"SELECT * FROM {table}").fetchall())
        if not rows:
            continue
        cols = [d[0] for d in conn.execute(f"SELECT * FROM {table} LIMIT 1").description]
        col_sql = ", ".join(cols)
        for row in rows:
            values = []
            for c in cols:
                v = row[c]
                # Avoid pushing enormous pipeline logs into D1 via --command; diagnostics only needs a tail.
                if table == "maths_pipeline_runs" and c == "log_text" and isinstance(v, str) and len(v) > 8000:
                    v = v[-8000:]
                values.append(sql_literal(v))
            values_sql = ", ".join(values)
            if table == "maths_questions":
                # Preserve manual edits to labels/topics in production.
                lines.append(f"INSERT OR IGNORE INTO {table} ({col_sql}) VALUES ({values_sql});")
            elif table == "maths_crops":
                # Preserve reviewed crops in production (conflicts will be ignored).
                lines.append(f"INSERT OR IGNORE INTO {table} ({col_sql}) VALUES ({values_sql});")
            else:
                lines.append(f"INSERT OR REPLACE INTO {table} ({col_sql}) VALUES ({values_sql});")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", "utf-8")


def migrate_remote_d1_columns(database_name: str) -> None:
    # Add new columns defensively. Ignore failures for "duplicate column name".
    commands = [
        "ALTER TABLE maths_crops ADD COLUMN status TEXT;",
        "ALTER TABLE maths_crops ADD COLUMN updated_at TEXT;",
    ]
    for sql in commands:
        proc = subprocess.run(
            ["npx", "wrangler", "d1", "execute", database_name, "--remote", "--command", sql],
            cwd=str(repo_root()),
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            continue
        stderr = (proc.stderr or "") + (proc.stdout or "")
        if "duplicate column name" in stderr.lower():
            continue
        raise RuntimeError(f"D1 migration failed: {sql}\n{stderr}")


def publish_assets_from_manifest(
    manifest_path: Path,
    *,
    kv_binding: str,
    asset_mode: str = "all",
) -> None:
    if not manifest_path.exists():
        raise FileNotFoundError(str(manifest_path))

    token = cloudflare_bearer_token()
    account_id, namespace_id = cloudflare_account_and_kv_namespace_id(kv_binding)

    # Chunk to stay comfortably under Cloudflare's API request limits.
    max_payload_bytes = 80_000_000
    batch: list[dict] = []
    batch_bytes = 0
    uploaded = 0

    def flush() -> None:
        nonlocal batch, batch_bytes, uploaded
        if not batch:
            return
        cloudflare_kv_bulk_put(
            account_id=account_id,
            namespace_id=namespace_id,
            token=token,
            items=batch,
        )
        uploaded += len(batch)
        print(f"KV bulk uploads: {uploaded}", flush=True)
        batch = []
        batch_bytes = 0

    for line in manifest_path.read_text("utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        key = str(item["key"])
        local_path = Path(str(item["path"]))
        content_type = str(item.get("contentType") or "application/octet-stream")

        if not local_path.exists():
            raise FileNotFoundError(str(local_path))

        key_lower = key.lower()
        if asset_mode == "pdfs":
            if not key_lower.endswith(".pdf"):
                continue
        elif asset_mode == "pdfs-thumbs":
            if not (key_lower.endswith(".pdf") or key_lower.endswith("/thumb.png")):
                continue
        elif asset_mode != "all":
            raise ValueError(f"Unknown asset_mode={asset_mode!r}")

        raw = local_path.read_bytes()
        b64 = base64.b64encode(raw).decode("ascii")
        entry = {
            "key": key,
            "value": b64,
            "base64": True,
            "metadata": {"contentType": content_type},
        }

        # Rough payload estimate; avoids encoding JSON repeatedly.
        est = len(key) + len(b64) + len(content_type) + 120
        if batch and (batch_bytes + est) > max_payload_bytes:
            flush()

        batch.append(entry)
        batch_bytes += est

        # Cloudflare API max is 10k keys per bulk call; keep well under.
        if len(batch) >= 2000:
            flush()

    flush()


def cmd_ingest(args: argparse.Namespace) -> int:
    db_path = Path(args.db).resolve()
    folder = Path(args.folder).resolve()
    root = repo_root()

    conn = dbmod.connect(db_path)
    try:
        dbmod.ensure_schema(conn, root)
        run_rec = dbmod.start_pipeline_run(conn, scope=f"ingest:{folder}")
        try:
            ids = ingest_folder(conn, folder, run_id=run_rec.id)
            dbmod.append_pipeline_log(conn, run_rec.id, f"INGEST complete files={len(ids)}")
            dbmod.finish_pipeline_run(conn, run_rec.id, status="ok")
        except Exception as exc:
            dbmod.append_pipeline_log(conn, run_rec.id, f"INGEST error: {exc}")
            dbmod.finish_pipeline_run(conn, run_rec.id, status="error")
            raise
    finally:
        conn.close()
    return 0


def cmd_segment(args: argparse.Namespace) -> int:
    db_path = Path(args.db).resolve()
    pdf_root = Path(args.pdf_root).resolve()
    root = repo_root()

    manifest = Path(args.asset_manifest).resolve()
    if manifest.exists():
        manifest.unlink()

    conn = dbmod.connect(db_path)
    try:
        dbmod.ensure_schema(conn, root)
        run_rec = dbmod.start_pipeline_run(conn, scope=f"segment:{pdf_root}")
        try:
            cfg = SegmentConfig(
                dpi=int(args.dpi),
                output_dir=Path(args.output_dir).resolve(),
                asset_manifest=manifest,
                force=bool(args.force),
            )
            segment_question_bank(
                conn,
                pdf_root,
                year=int(args.year) if args.year else None,
                paper=int(args.paper) if args.paper else None,
                file_id=args.file_id,
                config=cfg,
                run_id=run_rec.id,
            )
            dbmod.append_pipeline_log(conn, run_rec.id, "SEGMENT complete")
            dbmod.finish_pipeline_run(conn, run_rec.id, status="ok")
        except Exception as exc:
            dbmod.append_pipeline_log(conn, run_rec.id, f"SEGMENT error: {exc}")
            dbmod.finish_pipeline_run(conn, run_rec.id, status="error")
            raise
    finally:
        conn.close()
    return 0


def cmd_resegment(args: argparse.Namespace) -> int:
    # For now, this is just a segment run scoped to a file id.
    args.file_id = args.file_id
    return cmd_segment(args)


def cmd_publish(args: argparse.Namespace) -> int:
    # Push assets to KV + upsert DB rows into remote D1.
    db_path = Path(args.db).resolve()
    export_sql_path = Path(args.export_sql).resolve()
    manifest_path = Path(args.asset_manifest).resolve()
    database_name = str(args.d1_name)
    root = repo_root()

    conn = dbmod.connect(db_path)
    try:
        export_maths_sql(conn, export_sql_path)
    finally:
        conn.close()

    # Ensure maths schema exists remotely.
    # Use --command chunks instead of --file to avoid Cloudflare /import auth issues with OAuth tokens.
    execute_remote_d1_script(database_name, (root / "d1" / "schema.sql").read_text("utf-8"))

    migrate_remote_d1_columns(database_name)
    publish_assets_from_manifest(
        manifest_path,
        kv_binding=str(args.kv_binding),
        asset_mode=str(args.asset_mode),
    )
    execute_remote_d1_script(database_name, export_sql_path.read_text("utf-8"))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    # Best-effort local dev: build the frontend and run Pages dev server.
    # (Backend is still the deployed Worker unless the user runs `wrangler dev` separately.)
    env = os.environ.copy()
    env["API_BASE"] = env.get("API_BASE", "")

    subprocess.run(["npm", "run", "build"], cwd=str(repo_root()), check=True, env=env)
    subprocess.run(["npx", "wrangler", "pages", "dev", "dist", "--port", str(args.port)], cwd=str(repo_root()), check=True, env=env)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="maths", description="SQA Maths Question Bank pipeline")
    parser.set_defaults(func=None)

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="Index PDFs from a folder into the SQLite DB")
    p_ingest.add_argument("folder", help="Folder containing PDFs (question papers, mark schemes, datasheets)")
    p_ingest.add_argument("--db", default=str(default_db_path()), help="Path to local SQLite DB")
    p_ingest.set_defaults(func=cmd_ingest)

    p_segment = sub.add_parser("segment", help="Segment questions/answers and generate crop PNGs")
    p_segment.add_argument("--pdf-root", default=str(repo_root()), help="Root folder for PDF paths stored in maths_files.path")
    p_segment.add_argument("--db", default=str(default_db_path()), help="Path to local SQLite DB")
    p_segment.add_argument("--output-dir", default=str(repo_root() / "data" / "crops"), help="Output directory for generated crops")
    p_segment.add_argument("--asset-manifest", default=str(repo_root() / "data" / "maths-assets.jsonl"), help="JSONL manifest for assets to upload")
    p_segment.add_argument("--dpi", default="144", help="Render DPI for PNG crops")
    p_segment.add_argument("--year", help="Limit to a year")
    p_segment.add_argument("--paper", help="Limit to paper number (1 or 2)")
    p_segment.add_argument("--file-id", help="Limit to a specific maths_files.id")
    p_segment.add_argument("--force", action="store_true", help="Overwrite reviewed crops")
    p_segment.set_defaults(func=cmd_segment)

    p_reseg = sub.add_parser("resegment", help="Re-run segmentation for a specific file id")
    p_reseg.add_argument("--pdf-root", default=str(repo_root()), help="Root folder for PDF paths stored in maths_files.path")
    p_reseg.add_argument("--db", default=str(default_db_path()), help="Path to local SQLite DB")
    p_reseg.add_argument("--output-dir", default=str(repo_root() / "data" / "crops"), help="Output directory for generated crops")
    p_reseg.add_argument("--asset-manifest", default=str(repo_root() / "data" / "maths-assets.jsonl"), help="JSONL manifest for assets to upload")
    p_reseg.add_argument("--dpi", default="144", help="Render DPI for PNG crops")
    p_reseg.add_argument("--file-id", required=True, help="maths_files.id to resegment")
    p_reseg.add_argument("--force", action="store_true", help="Overwrite reviewed crops")
    p_reseg.set_defaults(func=cmd_resegment)

    p_serve = sub.add_parser("serve", help="Serve the frontend locally (best-effort)")
    p_serve.add_argument("--port", default="8789", help="Port for Pages dev server")
    p_serve.set_defaults(func=cmd_serve)

    p_pub = sub.add_parser("publish", help="Upload assets to KV and upsert DB into remote D1")
    p_pub.add_argument("--db", default=str(default_db_path()), help="Path to local SQLite DB")
    p_pub.add_argument("--asset-manifest", default=str(repo_root() / "data" / "maths-assets.jsonl"), help="Asset manifest JSONL")
    p_pub.add_argument("--export-sql", default=str(repo_root() / "data" / "maths-export.sql"), help="Generated SQL file for D1 upserts")
    p_pub.add_argument("--kv-binding", default="MATHS_ASSETS", help="Wrangler KV binding name")
    p_pub.add_argument("--d1-name", default="ruae-members-db", help="Wrangler D1 database name")
    p_pub.add_argument(
        "--asset-mode",
        default="all",
        choices=["pdfs-thumbs", "pdfs", "all"],
        help="Which assets to upload: PDFs only, PDFs + thumbs, or everything.",
    )
    p_pub.set_defaults(func=cmd_publish)

    args = parser.parse_args(argv)
    func = args.func
    if func is None:
        parser.print_help()
        return 2
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
