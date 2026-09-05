"""audit_log: sqlite (stdlib), таблица audit_log(user, action, target, scan_id, detail, ts)."""
from __future__ import annotations

import os
import sqlite3
import time
from .config import db_path_from_url

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  scan_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
"""


def _connect(database_url: str) -> sqlite3.Connection:
    path = db_path_from_url(database_url)
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL;")
    return con


def init_db(database_url: str) -> str:
    con = _connect(database_url)
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()
    return db_path_from_url(database_url)


def log_event(database_url: str, *, user: str = "", action: str,
              target: str = "", scan_id: str = "", detail: str = "") -> int:
    # Секреты и внутренние IP в detail сюда уже должны приходить очищенными для user-facing;
    # технические IP допускаются в audit log (не показываются пользователю при отказе).
    con = _connect(database_url)
    try:
        con.executescript(SCHEMA)
        cur = con.execute(
            "INSERT INTO audit_log(user, action, target, scan_id, detail, ts) VALUES(?,?,?,?,?,?)",
            (user or "", action, target or "", scan_id or "", detail or "", int(time.time())),
        )
        con.commit()
        return int(cur.lastrowid or 0)
    finally:
        con.close()


def recent(database_url: str, limit: int = 20) -> list[dict]:
    con = _connect(database_url)
    try:
        con.executescript(SCHEMA)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, user, action, target, scan_id, detail, ts FROM audit_log ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
