"""SQLite-backed catalog + state store for the query-history analyzer."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("QHA_DATA_DIR", os.path.join(ROOT, ".data"))
LAKE_DIR = os.path.join(DATA_DIR, "lake")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
DB_PATH = os.path.join(DATA_DIR, "catalog.db")

_init_lock = threading.Lock()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


def ensure_dirs() -> None:
    for d in (DATA_DIR, LAKE_DIR, BACKUP_DIR):
        os.makedirs(d, exist_ok=True)


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tables (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    partition_cols TEXT NOT NULL DEFAULT '[]',
    sort_keys TEXT NOT NULL DEFAULT '[]',
    columns_json TEXT NOT NULL DEFAULT '[]',
    row_count INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    file_count INTEGER NOT NULL DEFAULT 0,
    stats_updated_at TEXT,
    last_data_change_at TEXT,
    created_at TEXT NOT NULL,
    materialized_from TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL REFERENCES tables(name) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    partition_json TEXT NOT NULL DEFAULT '{}',
    row_count INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    stats_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_table ON files(table_name);

CREATE TABLE IF NOT EXISTS executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    query TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    table_name TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'history',
    client TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ok',
    error TEXT,
    duration_ms REAL NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    rows_scanned INTEGER NOT NULL DEFAULT 0,
    rows_returned INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_total INTEGER NOT NULL DEFAULT 0,
    files_pruned INTEGER NOT NULL DEFAULT 0,
    result_bytes INTEGER NOT NULL DEFAULT 0,
    plan_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_exec_fp ON executions(fingerprint);
CREATE INDEX IF NOT EXISTS idx_exec_ts ON executions(ts);

CREATE TABLE IF NOT EXISTS advisories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    table_name TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    rationale_json TEXT NOT NULL,
    sample_ids TEXT NOT NULL DEFAULT '[]',
    fingerprint TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id INTEGER NOT NULL REFERENCES advisories(id),
    ts TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    estimate_json TEXT NOT NULL,
    state_fingerprint TEXT NOT NULL,
    superseded INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rollback_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    apply_id INTEGER,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'available'
);

CREATE TABLE IF NOT EXISTS applies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id INTEGER NOT NULL REFERENCES advisories(id),
    simulation_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    status TEXT NOT NULL,
    before_json TEXT NOT NULL,
    after_json TEXT NOT NULL,
    rollback_point_id INTEGER,
    note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS undo_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    apply_id INTEGER,
    detail_json TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db() -> None:
    ensure_dirs()
    with _init_lock:
        conn = connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def is_initialized() -> bool:
    if not os.path.exists(DB_PATH):
        return False
    with db() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM tables").fetchone()
        return bool(row and row["n"])


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def _decode_table(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["partition_cols"] = json.loads(d["partition_cols"])
    d["sort_keys"] = json.loads(d["sort_keys"])
    d["columns"] = json.loads(d.get("columns_json") or "[]")
    d["stats_stale"] = bool(
        d["last_data_change_at"]
        and (not d["stats_updated_at"] or d["last_data_change_at"] > d["stats_updated_at"])
    )
    return d


def table_row(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM tables WHERE name=?", (name,)).fetchone()
    return _decode_table(row) if row else None


def list_tables(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM tables ORDER BY name").fetchall()
    return [_decode_table(row) for row in rows]


def file_rows(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM files WHERE table_name=? ORDER BY id", (table,)
    ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["partition"] = json.loads(d["partition_json"])
        d["stats"] = json.loads(d["stats_json"])
        out.append(d)
    return out


def refresh_table_aggregates(conn: sqlite3.Connection, table: str) -> None:
    row = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(bytes),0) AS b, COALESCE(SUM(row_count),0) AS r "
        "FROM files WHERE table_name=?",
        (table,),
    ).fetchone()
    conn.execute(
        "UPDATE tables SET file_count=?, bytes=?, row_count=? WHERE name=?",
        (row["n"], row["b"], row["r"], table),
    )


def log_undo(conn: sqlite3.Connection, action: str, apply_id: int | None, detail: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO undo_log(ts,action,apply_id,detail_json) VALUES(?,?,?,?)",
        (utcnow(), action, apply_id, json_dumps(detail)),
    )


def state_fingerprint(conn: sqlite3.Connection, table: str) -> str:
    """Fingerprint of physical layout + stats for one table.

    A simulation is only valid against the exact state it was computed from.
    """
    import hashlib

    rows = conn.execute(
        "SELECT rel_path, row_count, bytes, stats_json FROM files "
        "WHERE table_name=? ORDER BY rel_path",
        (table,),
    ).fetchall()
    t = conn.execute(
        "SELECT partition_cols, sort_keys, columns_json, stats_updated_at, last_data_change_at "
        "FROM tables WHERE name=?",
        (table,),
    ).fetchone()
    h = hashlib.sha256()
    for r in rows:
        h.update(f"{r['rel_path']}|{r['row_count']}|{r['bytes']}|{r['stats_json']}".encode())
    if t:
        h.update(f"{t['partition_cols']}|{t['sort_keys']}|{t['columns_json']}|{t['stats_updated_at']}|{t['last_data_change_at']}".encode())
    return h.hexdigest()[:24]


def sleep_ms(ms: float) -> None:
    time.sleep(max(0.0, ms) / 1000.0)
