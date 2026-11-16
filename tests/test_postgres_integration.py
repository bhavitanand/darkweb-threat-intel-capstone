"""The whole API running on a real Postgres. Skipped unless TEST_DATABASE_URL is set (CI provides a server)."""
import os

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

PG_URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set TEST_DATABASE_URL to run against Postgres")


@pytest.fixture
def client(monkeypatch):
    from darklens.store import db

    c = db.PgConnection(PG_URL)
    c.executescript(db.SCHEMA)
    for t in ("items", "alerts", "iocs", "watchlist", "feedback", "kv", "notified"):
        c.execute(f"DELETE FROM {t}")
    c.commit()
    c.close()
    db._pg_singletons.clear()
    module = load_app(monkeypatch, DATABASE_URL=PG_URL)
    with TestClient(module.app) as client:
        yield client
    for con in list(db._pg_singletons.values()):
        con.close()
    db._pg_singletons.clear()


def test_health_reports_postgres(client):
    assert client.get("/api/health").json()["storage"] == "postgres"


def test_demo_data_seeds_and_reads_back(client):
    rows = client.get("/api/alerts").json()
    assert len(rows) >= 10 and all(r["demo"] for r in rows)
    assert any(r["iocs"] for r in rows) and client.get("/api/stats").json()["alerts"] == len(rows)
    assert client.get("/api/graph").json()["graph"]["nodes"]


def test_watchlist_rescore_and_alert_detail(client):
    before = {r["item_id"]: r["score"] for r in client.get("/api/alerts").json()}
    assert client.post("/api/watchlist", json={"kind": "domain", "value": "granite-bank.example"}).status_code == 200
    after = {r["item_id"]: r["score"] for r in client.get("/api/alerts").json()}
    assert max(after[k] - before[k] for k in before) > 0  # the credential dump aimed at that domain jumps
    detail = client.get(f"/api/alerts/{next(iter(after))}").json()
    assert detail["mitre"] is not None and detail["feedback"] == {"correct": 0, "wrong": 0}


def test_feedback_and_exports(client):
    item = client.get("/api/alerts").json()[0]["item_id"]
    assert client.post(f"/api/alerts/{item}/feedback", json={"verdict": "correct"}).json() == {"correct": 1, "wrong": 0}
    assert client.get("/api/feedback/summary").json()["total"] == 1
    assert "text,label" in client.get("/api/export/feedback.csv").text
    assert client.get("/api/export/alerts.csv").text.startswith("id,")
    assert client.get("/api/export/stix.json").json()["type"] == "bundle"


def test_ingest_status_and_prune_use_postgres_correctly(client):
    from darklens.store import db

    st = client.get("/api/ingest/status").json()
    assert st["last"]["mode"] == "demo"
    assert db.prune(db.connect(), "2000-01-01") == 0  # exercises the LIKE with a literal percent on Postgres
