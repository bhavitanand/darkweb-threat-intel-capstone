"""API-level tests for the 'mature project' features: feedback, validation, tokens, live re-scoring, exports."""
import csv
import io

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import pipeline
from darklens.models import Item
from darklens.store import db


@pytest.fixture
def client(monkeypatch):
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


def _first_id(client):
    return client.get("/api/alerts").json()[0]["item_id"]


# ---- demo flag and stats ----

def test_seeded_data_is_flagged_as_demo(client):
    rows = client.get("/api/alerts").json()
    assert rows and all(r["demo"] is True for r in rows)
    s = client.get("/api/stats").json()
    assert s["demo_alerts"] == s["alerts"] and s["real_alerts"] == 0


def test_alerts_list_has_indicators_and_respects_limit(client):
    assert any(r["iocs"] for r in client.get("/api/alerts").json())
    assert len(client.get("/api/alerts?limit=3").json()) == 3


# ---- watchlist validation and re-scoring everything ----

@pytest.mark.parametrize("kind,value", [("domain", "not a domain"), ("domain", "localhost"), ("email", "a@b"),
                                        ("url", "example.com"), ("domain", ""), ("domain", "x" * 300)])
def test_watchlist_rejects_bad_values(client, kind, value):
    assert client.post("/api/watchlist", json={"kind": kind, "value": value}).status_code in (400, 422)


def test_watchlist_normalises_and_rescores_live_items_too(client):
    """A watchlist entry must re-score real (non-demo) data, not only the demo set."""
    con = client.module.con()
    live = Item(source="ransomware.live", kind="post", title="Fresh dump",
                text="Selling database dump. ceo@acme-corp.example:Sup3rSecret1 cfo@acme-corp.example:Hunter2xx "
                     "it@acme-corp.example:Passw0rd99 emails and passwords")
    pipeline.run(items=[live], con=con)
    before = next(r for r in client.get("/api/alerts").json() if r["title"] == "Fresh dump")
    assert before["demo"] is False and not any("watched" in s["name"] for s in before["signals"])
    r = client.post("/api/watchlist", json={"kind": "domain", "value": "  ACME-Corp.Example "})
    assert r.status_code == 200 and {"kind": "domain", "value": "acme-corp.example"} in r.json()
    after = next(x for x in client.get("/api/alerts").json() if x["title"] == "Fresh dump")
    assert after["score"] > before["score"]
    assert any(s["name"].startswith("Credentials for watched") for s in after["signals"])
    stored = con.execute("SELECT text FROM items WHERE title='Fresh dump'").fetchone()["text"]
    assert "Sup3rSecret1" not in stored  # passwords are never stored in plaintext


# ---- sources that forbid re-publishing their data (Ransomware.live terms, section 4) ----

CLAIM_TEXT = "Secret Corp was claimed by PixelLeaks. Sector: Finance. Deadline: 2026-12-01. SECRET-DESCRIPTION"


def _store_claim(client, title="PixelLeaks: Secret Corp", restricted=True, with_iocs=True):
    meta = {"attribution": "Source: Ransomware.live"}
    if restricted:
        meta["no_redistribute"] = True
    text = CLAIM_TEXT + (" contact 8.8.8.8" if with_iocs else "")
    it = Item(source="ransomware.live", kind="leak_claim", title=title, text=text, actor="PixelLeaks",
              url="https://www.ransomware.live/id/abc", meta=meta)
    pipeline.run(items=[it], con=client.module.con())
    return it


def test_restricted_alert_withholds_its_raw_text_everywhere_in_the_api(client):
    it = _store_claim(client)
    listed = next(r for r in client.get("/api/alerts").json() if r["title"] == "PixelLeaks: Secret Corp")
    assert listed["restricted"] is True and listed["text"] == "" and listed["demo"] is False
    one = client.get(f"/api/alerts/{it.id}").json()
    assert one["text"] == "" and one["url"] == "https://www.ransomware.live/id/abc"  # the link back is kept
    assert "SECRET-DESCRIPTION" not in client.get(f"/api/alerts/{it.id}/evidence").text
    assert "SECRET-DESCRIPTION" not in client.get("/api/graph").text
    assert any(s["name"] == "Listed on a leak-site tracker" for s in one["signals"])  # scoring still used the text


def test_restricted_alerts_are_left_out_of_every_export(client):
    it = _store_claim(client)
    _store_claim(client, title="Free thing", restricted=False)
    csv_text = client.get("/api/export/alerts.csv").text
    assert "Secret Corp" not in csv_text and "Free thing" in csv_text
    stix = client.get("/api/export/stix.json").text
    assert "Secret Corp" not in stix and "SECRET-DESCRIPTION" not in stix and "Free thing" in stix
    client.post(f"/api/alerts/{it.id}/feedback", json={"verdict": "correct"})
    assert "Secret" not in client.get("/api/export/feedback.csv").text
    assert client.get("/api/feedback/summary").json()["total"] == 1  # still counted for accuracy, just not exported


def test_demo_data_remains_exportable(client):
    rows = list(csv.DictReader(io.StringIO(client.get("/api/export/alerts.csv").text)))
    assert len(rows) == client.get("/api/stats").json()["alerts"] > 0


# ---- analyse input limits ----

def test_analyse_rejects_oversized_text(client):
    assert client.post("/api/analyse", json={"text": "a" * 20001}).status_code == 422
    assert client.post("/api/analyse", json={"text": "hello there"}).status_code == 200


# ---- ingest token and status ----

def test_ingest_is_open_without_a_token_configured(client):
    assert client.post("/api/ingest").status_code == 200


def test_ingest_requires_the_token_when_configured(monkeypatch):
    module = load_app(monkeypatch, INGEST_TOKEN="s3cret")
    with TestClient(module.app) as c:
        assert c.post("/api/ingest").status_code == 401
        assert c.post("/api/ingest", headers={"X-Ingest-Token": "wrong"}).status_code == 401
        assert c.post("/api/ingest", headers={"X-Ingest-Token": "s3cret"}).status_code == 200


def test_ingest_status_reports_the_last_run(client):
    st = client.get("/api/ingest/status").json()
    assert st["last"]["mode"] == "demo" and st["live_ready"] is False
    assert {s["source"] for s in st["last"]["sources"]} == {"ransomware.live", "threatfox", "forums"}


# ---- feedback loop ----

def test_feedback_correct_and_wrong_flow(client):
    item = _first_id(client)
    cat = client.get(f"/api/alerts/{item}").json()["category"]
    assert client.post(f"/api/alerts/{item}/feedback", json={"verdict": "correct"}).json() == {"correct": 1, "wrong": 0}
    other = "phishing_kit" if cat != "phishing_kit" else "malware_sale"
    # the same visitor changes their mind: still one vote
    assert client.post(f"/api/alerts/{item}/feedback", json={"verdict": "wrong", "category": other}).json() == \
        {"correct": 0, "wrong": 1}
    s = client.get("/api/feedback/summary").json()
    assert s["total"] == 1 and s["wrong"] == 1 and s["agreement"] == 0.0
    assert s["corrections"] == {f"{cat} -> {other}": 1}


@pytest.mark.parametrize("body", [
    {"verdict": "maybe"}, {"verdict": "wrong"}, {"verdict": "wrong", "category": "not_a_category"},
    {"verdict": "wrong", "category": ""},
])
def test_feedback_rejects_bad_input(client, body):
    assert client.post(f"/api/alerts/{_first_id(client)}/feedback", json=body).status_code == 400


def test_feedback_rejects_saying_wrong_with_the_same_category(client):
    item = _first_id(client)
    cat = client.get(f"/api/alerts/{item}").json()["category"]
    assert client.post(f"/api/alerts/{item}/feedback", json={"verdict": "wrong", "category": cat}).status_code == 400


def test_feedback_on_unknown_alert_is_404(client):
    assert client.post("/api/alerts/nope/feedback", json={"verdict": "correct"}).status_code == 404


def test_feedback_export_is_labelled_csv(client):
    item = _first_id(client)
    client.post(f"/api/alerts/{item}/feedback", json={"verdict": "correct"})
    reply = client.get("/api/export/feedback.csv")
    assert reply.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(reply.text)))
    assert len(rows) == 1 and rows[0]["item_id"] == item and rows[0]["label"] == rows[0]["predicted"]


# ---- exports ----

def test_csv_export_has_every_alert_and_a_header(client):
    reply = client.get("/api/export/alerts.csv")
    assert "attachment" in reply.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(reply.text)))
    assert len(rows) == client.get("/api/stats").json()["alerts"]
    assert {"id", "severity", "score", "category", "title", "indicators"} <= set(rows[0])


def test_stix_export_is_a_bundle(client):
    reply = client.get("/api/export/stix.json")
    assert reply.headers["content-type"].startswith("application/stix+json")
    bundle = reply.json()
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    assert any(o["type"] == "report" for o in bundle["objects"])


def test_health_reports_storage_without_leaking_secrets(client):
    body = client.get("/api/health").json()
    assert body["storage"] == "sqlite" and "url" not in str(body).lower()


# ---- retention ----

def test_prune_removes_old_real_items_but_keeps_demo_and_labelled(client):
    con = client.module.con()
    old = Item(source="ransomware.live", kind="post", title="Old", text="ransom will be published", seen_at="2020-01-01")
    labelled = Item(source="ransomware.live", kind="post", title="Labelled", text="ransom negotiation", seen_at="2020-01-02")
    pipeline.run(items=[old, labelled], con=con)
    db.feedback_set(con, labelled.id, "v", "correct", "ransomware_leak", "t")
    removed = db.prune(con, "2021-01-01")
    titles = {r["title"] for r in client.get("/api/alerts").json()}
    assert removed == 1 and "Old" not in titles and "Labelled" in titles
    assert any(r["demo"] for r in client.get("/api/alerts").json())  # demo data untouched
