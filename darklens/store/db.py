"""Store for items, alerts, IOCs, the watchlist, analyst feedback and small bits of state.

Two back ends behind one tiny interface (`execute`, `executescript`, `commit`):

* SQLite (default): zero setup, one file. Fine for local use, tests and demos.
* Postgres: set `DATABASE_URL` (for example a free Neon or Supabase database). Data then survives restarts of a
  free host. All SQL below is written in the common subset (`ON CONFLICT ... DO UPDATE`, `?` placeholders that
  the Postgres adapter rewrites), so there is one code path to keep correct.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

def default_db_path() -> Path:
    """The SQLite file, read from the environment each time so tests and tools can point elsewhere."""
    return Path(os.environ.get("DARKLENS_DB", Path(__file__).resolve().parents[2] / "darklens.db"))

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
CREATE TABLE IF NOT EXISTS feedback (
  item_id TEXT, voter TEXT, verdict TEXT, category TEXT, created_at TEXT,
  PRIMARY KEY (item_id, voter)
);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS notified (
  item_id TEXT, channel TEXT, created_at TEXT, PRIMARY KEY (item_id, channel)
);
"""


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


class Rows:
    """Result of an `execute`: already fetched, so the connection lock is never held while the caller iterates."""

    def __init__(self, rows: list):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list:
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


def to_pg(sql: str) -> str:
    """Rewrite SQLite-style SQL for psycopg: `?` placeholders become `%s`, literal `%` is escaped."""
    return sql.replace("%", "%%").replace("?", "%s")


class PgConnection:
    """Thin psycopg wrapper with the same surface the rest of the code uses, plus reconnect-on-drop.

    One shared connection per process, guarded by a lock. Free hosted Postgres closes idle connections, so a
    dropped connection is re-opened once and the statement retried. Reads end their transaction immediately;
    writes stay open until `commit()` so a whole ingest run is one transaction.
    """

    dialect = "postgres"

    def __init__(self, url: str, connect=None):
        self.url = url
        self._connect_fn = connect
        self._lock = threading.RLock()
        self._conn = None
        self._open()

    def _open(self):
        if self._connect_fn is not None:
            self._conn = self._connect_fn(self.url)
            return
        import psycopg
        from psycopg.rows import dict_row

        # prepare_threshold=None: hosted poolers (Neon, Supabase) can drop server-side prepared statements.
        self._conn = psycopg.connect(self.url, row_factory=dict_row, connect_timeout=15, prepare_threshold=None)

    def _reconnect(self):
        try:
            self._conn.close()
        except Exception:
            pass
        self._open()

    def execute(self, sql: str, params: tuple = ()) -> Rows:
        sql = to_pg(sql)
        with self._lock:
            for attempt in (0, 1):
                try:
                    cur = self._conn.execute(sql, params)
                    rows = cur.fetchall() if cur.description else []
                    if cur.description:  # a read: close the transaction so the connection is never left idle in one
                        self._conn.commit()
                    return Rows(rows)
                except Exception as e:  # noqa: BLE001 - driver-specific connection errors
                    name = type(e).__name__
                    if attempt == 0 and name in ("OperationalError", "InterfaceError", "AdminShutdown"):
                        self._reconnect()
                        continue
                    try:
                        self._conn.rollback()
                    except Exception:
                        pass
                    raise
        raise RuntimeError("unreachable")

    def executescript(self, script: str) -> None:
        for stmt in (s.strip() for s in script.split(";")):
            if stmt:
                self.execute(stmt)
        self.commit()

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_pg_singletons: dict[str, PgConnection] = {}


def connect(path: Path | str | None = None):
    """Open the store. An explicit `path` always means SQLite; otherwise `DATABASE_URL` selects Postgres."""
    url = database_url()
    if path is None and url:
        con = _pg_singletons.get(url)
        if con is None:
            con = PgConnection(url)
            con.executescript(SCHEMA)
            _pg_singletons[url] = con
        return con
    con = sqlite3.connect(str(path or default_db_path()), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def _upsert(table: str, cols: list[str], key: list[str]) -> str:
    updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c not in key)
    tail = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
    return (f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
            f"ON CONFLICT({', '.join(key)}) {tail}")


ITEM_COLS = ["id", "source", "kind", "title", "text", "url", "seen_at", "actor", "org", "country", "meta"]
ALERT_COLS = ["item_id", "category", "confidence", "score", "severity", "signals", "probs", "created_at"]


def upsert_item(con, item) -> None:
    con.execute(_upsert("items", ITEM_COLS, ["id"]),
                (item.id, item.source, item.kind, item.title, item.text, item.url, item.seen_at,
                 item.actor, item.org, item.country, json.dumps(item.meta)))


def upsert_alert(con, item_id, category, confidence, score, severity, signals, probs, created_at) -> None:
    con.execute(_upsert("alerts", ALERT_COLS, ["item_id"]),
                (item_id, category, confidence, score, severity,
                 json.dumps([s.to_dict() for s in signals]), json.dumps(probs), created_at))


def alert_delete(con, item_id: str) -> None:
    con.execute("DELETE FROM alerts WHERE item_id=?", (item_id,))


def prune(con, before: str, kinds: tuple = (), exclude_kinds: tuple = ()) -> int:
    """Delete real (non-demo) items last seen before `before` (YYYY-MM-DD) with their alerts and indicators.
    `kinds` limits it to those item kinds, `exclude_kinds` skips them (so indicator feeds can expire sooner than
    claims and posts). Items an analyst has given feedback on are kept, because they are labelled training data."""
    sql = ("SELECT id FROM items WHERE seen_at <> '' AND seen_at < ? AND meta NOT LIKE '%\"demo\"%' "
           "AND id NOT IN (SELECT item_id FROM feedback)")
    args: list = [before]
    if kinds:
        sql += f" AND kind IN ({','.join('?' * len(kinds))})"
        args += list(kinds)
    if exclude_kinds:
        sql += f" AND kind NOT IN ({','.join('?' * len(exclude_kinds))})"
        args += list(exclude_kinds)
    ids = [r["id"] for r in con.execute(sql, tuple(args))]
    for i in ids:
        for table, col in (("alerts", "item_id"), ("iocs", "item_id"), ("items", "id")):
            con.execute(f"DELETE FROM {table} WHERE {col}=?", (i,))
    con.commit()
    return len(ids)


def add_iocs(con, item_id, iocs: dict[str, list[str]]) -> None:
    for typ, vals in iocs.items():
        for v in vals:
            con.execute(_upsert("iocs", ["item_id", "type", "value"], ["item_id", "type", "value"]), (item_id, typ, v))


def watch_add(con, kind: str, value: str) -> None:
    con.execute(_upsert("watchlist", ["kind", "value"], ["kind", "value"]), (kind, value.strip().lower()))
    con.commit()


def watch_all(con) -> list[tuple[str, str]]:
    return [(r["kind"], r["value"]) for r in con.execute("SELECT kind, value FROM watchlist")]


# ---- small key/value state (ingest status and similar) ----

def kv_set(con, key: str, value) -> None:
    con.execute(_upsert("kv", ["key", "value"], ["key"]), (key, json.dumps(value)))
    con.commit()


def kv_get(con, key: str, default=None):
    row = con.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


# ---- analyst feedback ----

def feedback_set(con, item_id: str, voter: str, verdict: str, category: str, created_at: str) -> None:
    con.execute(_upsert("feedback", ["item_id", "voter", "verdict", "category", "created_at"], ["item_id", "voter"]),
                (item_id, voter, verdict, category, created_at))
    con.commit()


def feedback_all(con) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT f.item_id, f.verdict, f.category, f.created_at, a.category AS predicted, i.title, i.text, i.meta "
        "FROM feedback f JOIN alerts a ON a.item_id=f.item_id JOIN items i ON i.id=f.item_id "
        "ORDER BY f.created_at DESC")]


# ---- notifications already sent ----

def notified_has(con, item_id: str, channel: str) -> bool:
    return con.execute("SELECT 1 AS x FROM notified WHERE item_id=? AND channel=?", (item_id, channel)).fetchone() is not None


def notified_add(con, item_id: str, channel: str, created_at: str) -> None:
    con.execute(_upsert("notified", ["item_id", "channel", "created_at"], ["item_id", "channel"]),
                (item_id, channel, created_at))
    con.commit()

