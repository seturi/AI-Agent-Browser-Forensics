"""SQLite reader (stdlib sqlite3) — functional.

For Cookies, Login Data, browseros.db, and Fellou sqliteDatabase.db. Opens the
file read-only via a file: URI so a forensic copy is never modified, and
tolerates a missing -wal/-shm by querying immutably.

Note: cookie/login *values* are often DPAPI/AES-GCM encrypted; this reader
returns them raw. Decryption is a separate concern (per-service / Windows DPAPI).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def _connect(db_path: Path) -> sqlite3.Connection:
    # immutable=1 => read-only, no locking, ignores -wal (safe on copies).
    uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def list_tables(db_path: Path) -> list[str]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    return [r["name"] for r in rows]


def read_table(db_path: Path, table: str, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Return all rows of ``table`` as dicts. ``table`` is validated against the
    schema to avoid SQL injection via identifier interpolation."""
    with _connect(db_path) as conn:
        valid = {
            r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if table not in valid:
            raise ValueError(f"no such table: {table}")
        sql = f'SELECT * FROM "{table}"'
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return [dict(r) for r in conn.execute(sql).fetchall()]


def query(db_path: Path, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Run an arbitrary read-only query and return rows as dicts."""
    with _connect(db_path) as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
