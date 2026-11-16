"""Store tests. The same behaviour tests run on SQLite always, and on real Postgres when TEST_DATABASE_URL is
set (CI does this with a Postgres service container)."""
import os

import pytest

from darklens.models import Item, Signal
from darklens.store import db

PG_URL = os.environ.get("TEST_DATABASE_URL", "")


@pytest.fixture(params=["sqlite"] + (["postgres"] if PG_URL else []))
def con(request, tmp_path):
    if request.param == "sqlite":
        c = db.connect(tmp_path / "s.db")
        yield c
        c.close()
    else:
        c = db.PgConnection(PG_URL)
        c.executescript(db.SCHEMA)
        for t in ("items", "alerts", "iocs", "watchlist", "feedback", "kv", "notified"):
            c.execute(f"DELETE FROM {t}")
        c.commit()
        yield c
        c.close()


def _item(**kw):
    base = dict(source="test", kind="post", title="Hello", text="body text", actor="a", org="o", country="IN")
    base.update(kw)
    return Item(**base)


def test_item_upsert_is_idempotent_and_updates(con):
    it = _item()
    db.upsert_item(con, it)
    db.upsert_item(con, it)
    it.country = "US"
    db.upsert_item(con, it)
    con.commit()
    rows = con.execute("SELECT * FROM items").fetchall()
    assert len(rows) == 1 and rows[0]["country"] == "US"


def test_alert_upsert_replaces_and_roundtrips_json(con):
    it = _item()
    db.upsert_item(con, it)
    sig = [Signal("S", 50, "because")]
    db.upsert_alert(con, it.id, "benign", 0.5, 10, "low", sig, {"benign": 1.0}, "2026-01-01T00:00:00Z")
    db.upsert_alert(con, it.id, "ransomware_leak", 0.9, 90, "critical", sig, {"x": 1.0}, "2026-01-02T00:00:00Z")
    con.commit()
    rows = con.execute("SELECT a.*, i.title FROM alerts a JOIN items i ON i.id=a.item_id").fetchall()
    assert len(rows) == 1 and rows[0]["score"] == 90 and rows[0]["title"] == "Hello"


def test_iocs_are_deduplicated(con):
    db.add_iocs(con, "x", {"btc": ["a", "a", "b"], "email": ["e@x.com"]})
    db.add_iocs(con, "x", {"btc": ["a"]})
    con.commit()
    assert con.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"] == 3


def test_watchlist_normalises_and_dedupes(con):
    db.watch_add(con, "domain", "  Example.COM ")
    db.watch_add(con, "domain", "example.com")
    assert db.watch_all(con) == [("domain", "example.com")]


def test_kv_roundtrip_and_default(con):
    assert db.kv_get(con, "nope", {"d": 1}) == {"d": 1}
    db.kv_set(con, "k", {"a": [1, 2]})
    db.kv_set(con, "k", {"a": [3]})
    assert db.kv_get(con, "k") == {"a": [3]}


def test_feedback_is_one_vote_per_voter_and_joins_the_alert(con):
    it = _item()
    db.upsert_item(con, it)
    db.upsert_alert(con, it.id, "benign", 0.5, 10, "low", [], {}, "t")
    con.commit()
    db.feedback_set(con, it.id, "v1", "wrong", "ransomware_leak", "2026-01-01T00:00:00Z")
    db.feedback_set(con, it.id, "v1", "correct", "benign", "2026-01-02T00:00:00Z")
    db.feedback_set(con, it.id, "v2", "wrong", "phishing_kit", "2026-01-03T00:00:00Z")
    rows = db.feedback_all(con)
    assert len(rows) == 2
    assert {r["verdict"] for r in rows} == {"correct", "wrong"}
    assert all(r["predicted"] == "benign" for r in rows)


def test_notified_tracking(con):
    assert not db.notified_has(con, "i", "webhook")
    db.notified_add(con, "i", "webhook", "t")
    db.notified_add(con, "i", "webhook", "t")
    assert db.notified_has(con, "i", "webhook") and not db.notified_has(con, "i", "email")


# ---- Postgres adapter, exercised without a server using a fake driver ----

def test_to_pg_rewrites_placeholders_and_escapes_percent():
    assert db.to_pg("SELECT * FROM t WHERE a=? AND b LIKE '50%' AND c=?") == \
        "SELECT * FROM t WHERE a=%s AND b LIKE '50%%' AND c=%s"


class _Cur:
    def __init__(self, rows, description=True):
        self._rows, self.description = rows, ([("c",)] if description and rows is not None else None)

    def fetchall(self):
        return self._rows


class FakePg:
    class OperationalError(Exception):
        pass

    def __init__(self, fail_first=0):
        self.statements, self.commits, self.rollbacks, self.fail_first, self.closed = [], 0, 0, fail_first, False

    def execute(self, sql, params=()):
        if self.fail_first:
            self.fail_first -= 1
            raise type("OperationalError", (Exception,), {})("server closed the connection")
        self.statements.append((sql, params))
        return _Cur([{"c": 1}]) if sql.startswith("SELECT") else _Cur(None)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def test_pg_adapter_translates_reads_commit_and_writes_wait():
    fake = FakePg()
    con = db.PgConnection("postgresql://x", connect=lambda url: fake)
    assert con.execute("SELECT COUNT(*) c FROM t WHERE a=?", ("v",)).fetchone() == {"c": 1}
    assert fake.statements[-1] == ("SELECT COUNT(*) c FROM t WHERE a=%s", ("v",))
    assert fake.commits == 1  # a read ends its transaction at once
    con.execute("INSERT INTO t VALUES (?)", (1,))
    assert fake.commits == 1  # a write stays open until commit()
    con.commit()
    assert fake.commits == 2


def test_pg_adapter_reconnects_once_when_the_connection_dropped():
    first, second = FakePg(fail_first=1), FakePg()
    conns = iter([first, second])
    con = db.PgConnection("postgresql://x", connect=lambda url: next(conns))
    assert con.execute("SELECT 1").fetchone() == {"c": 1}
    assert first.closed and second.statements


def test_pg_adapter_rolls_back_and_raises_on_other_errors():
    fake = FakePg()

    def boom(sql, params=()):
        raise ValueError("syntax error")

    fake.execute = boom
    con = db.PgConnection("postgresql://x", connect=lambda url: fake)
    with pytest.raises(ValueError):
        con.execute("SELEKT")
    assert fake.rollbacks == 1


def test_connect_uses_sqlite_for_explicit_paths_even_if_database_url_is_set(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "postgresql://never-contacted")
    c = db.connect(tmp_path / "x.db")
    assert not hasattr(c, "dialect")
    c.close()
