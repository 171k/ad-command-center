"""SQLite data layer with WAL mode for safe multi-session concurrency.

Design notes:
- WAL lets multiple readers run concurrently with a single writer, which is
  sufficient for 4 simultaneous browser sessions plus bounded ingest workers.
- busy_timeout handles the brief writer contention under event bursts.
- A thin migration runner applies ordered .sql files once and records them.
- All queries elsewhere use parameter binding (never string interpolation) to
  prevent SQL injection.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .config import get_settings

_local = threading.local()
_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _connect() -> sqlite3.Connection:
    s = get_settings()
    conn = sqlite3.connect(
        s.db_path, timeout=10.0, isolation_level=None, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=10000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def get_conn() -> sqlite3.Connection:
    """One connection per thread (FastAPI threadpool / worker)."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


def query(sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    return get_conn().execute(sql, tuple(params)).fetchall()


def query_one(sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
    return get_conn().execute(sql, tuple(params)).fetchone()


def execute(sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
    return get_conn().execute(sql, tuple(params))


def executemany(sql: str, seq: Iterable[Iterable[Any]]) -> sqlite3.Cursor:
    return get_conn().executemany(sql, [tuple(p) for p in seq])


def transaction():
    return _Txn(get_conn())


class _Txn:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self.conn.execute("BEGIN;")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.conn.execute("COMMIT;")
        else:
            self.conn.execute("ROLLBACK;")


def run_migrations() -> list[str]:
    """Apply any unapplied *.sql migrations in filename order. Idempotent."""
    conn = get_conn()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));"
    )
    applied = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
    newly: list[str] = []
    for path in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        if path.name in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        conn.executescript(sql)
        conn.execute("INSERT INTO schema_migrations(name) VALUES (?)", (path.name,))
        newly.append(path.name)
    return newly
