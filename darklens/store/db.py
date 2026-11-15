"""SQLite store for items, alerts, IOCs and the watchlist. Zero setup, one file."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("DARKLENS_DB", Path(__file__).resolve().parents[2] / "darklens.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY, source TEXT, kind TEXT, title TEXT, text TEXT, url TEXT,
  seen_at TEXT, actor TEXT, org TEXT, country TEXT, meta TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  item_id TEXT PRIMARY KEY, category TEXT, confidence REAL, score INTEGER, severity TEXT,
  signals TEXT, probs TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
  item_id TEXT, type TEXT, value TEXT, PRIMARY KEY (item_id, type, value)
);
CREATE INDEX IF NOT EXISTS ix_iocs_value ON iocs(value);
CREATE TABLE IF NOT EXISTS watchlist (
  kind TEXT, value TEXT, PRIMARY KEY (kind, value)
);
"""


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    con = sqlite3.connect(str(path or DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def upsert_item(con, item) -> None:
    con.execute(
        "INSERT OR REPLACE INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (item.id, item.source, item.kind, item.title, item.text, item.url, item.seen_at,
         item.actor, item.org, item.country, json.dumps(item.meta)),
    )


def upsert_alert(con, item_id, category, confidence, score, severity, signals, probs, created_at) -> None:
    con.execute(
        "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?)",
        (item_id, category, confidence, score, severity,
         json.dumps([s.to_dict() for s in signals]), json.dumps(probs), created_at),
    )


def add_iocs(con, item_id, iocs: dict[str, list[str]]) -> None:
    for typ, vals in iocs.items():
        for v in vals:
            con.execute("INSERT OR IGNORE INTO iocs VALUES (?,?,?)", (item_id, typ, v))


def watch_add(con, kind: str, value: str) -> None:
    con.execute("INSERT OR IGNORE INTO watchlist VALUES (?,?)", (kind, value.strip().lower()))
    con.commit()


def watch_all(con) -> list[tuple[str, str]]:
    return [(r["kind"], r["value"]) for r in con.execute("SELECT kind, value FROM watchlist")]
