"""Edge cases in the data layer: malformed feed records, damaged cache, nasty text in exports and evidence packs,
odd dates, and concurrent requests."""
import csv
import io
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import export, pipeline
from darklens.collectors import base, cisa_kev, ransomware_live, threatfox, urlhaus
from darklens.models import Item
from darklens.store import db


@pytest.fixture
def client(monkeypatch):
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


WEIRD = [None, 0, 1, 1.5, True, "", "   ", [], {}, ["a"], {"a": 1}, "x" * 10000, "\x00", "💀", b"bytes", float("nan")]


# ---------------- feed records with fields of the wrong type ----------------

@pytest.mark.parametrize("value", WEIRD, ids=lambda v: repr(v)[:20])
def test_ransomware_live_record_with_a_weird_field_never_crashes(value):
    for field in ("victim", "group", "activity", "website", "description", "permalink", "attackdate", "country"):
        it = ransomware_live._to_item({field: value, "victim": "Acme", "group": "grp"} if field not in ("victim", "group") else {field: value})
        assert isinstance(it.title, str) and isinstance(it.text, str) and len(it.text) < 12000 and len(it.seen_at) <= 10


@pytest.mark.parametrize("value", WEIRD, ids=lambda v: repr(v)[:20])
def test_threatfox_and_urlhaus_records_with_weird_fields_are_handled(value):
    body = {"query_status": "ok", "data": [{"ioc": "1.2.3.4:80", **{k: value for k in ("malware", "malware_printable", "threat_type", "confidence_level", "first_seen", "ioc_type")}}]}
    for it in threatfox.parse(body):
        assert isinstance(it.text, str) and isinstance(it.title, str)
    body = {"query_status": "ok", "urls": [{"url": "http://x.test/a", **{k: value for k in ("host", "tags", "url_status", "date_added", "threat", "urlhaus_reference")}}]}
    for it in urlhaus.parse(body):
        assert isinstance(it.text, str) and isinstance(it.meta["confidence"], int)


@pytest.mark.parametrize("value", WEIRD, ids=lambda v: repr(v)[:20])
def test_cisa_record_with_weird_fields_is_handled(value):
    it = cisa_kev._to_item({"cveID": "CVE-2026-1", **{k: value for k in ("vendorProject", "product", "vulnerabilityName", "shortDescription", "knownRansomwareCampaignUse", "dateAdded")}})
    assert isinstance(it.text, str) and it.meta["cve"] == "CVE-2026-1"


@pytest.mark.parametrize("body", [[], "text", 5, None])
def test_feed_answers_that_are_not_objects_raise_a_clear_error(body):
    for parse in (threatfox.parse, urlhaus.parse):
        with pytest.raises(RuntimeError):
            parse(body)


@pytest.mark.parametrize("body", [{"query_status": "ok", "data": "oops"}, {"query_status": "ok", "data": None},
                                  {"query_status": "ok", "data": [1, "a", None, [], {}]}, {"query_status": "no_result"},
                                  {"query_status": "ok", "data": [{"ioc": ""}, {"ioc": None}]}])
def test_threatfox_tolerates_every_documented_and_odd_shape(body):
    assert threatfox.parse(body) == []


def test_threatfox_wrong_key_status_is_an_error_not_silence():
    with pytest.raises(RuntimeError):
        threatfox.parse({"query_status": "unknown_auth_key"})


def test_live_claims_fetch_rejects_a_non_list_answer(monkeypatch):
    monkeypatch.setenv(ransomware_live.KEY_ENV, "k")
    monkeypatch.setattr(ransomware_live, "cached_get", lambda *a, **k: "not a list")
    with pytest.raises(RuntimeError):
        ransomware_live.fetch(offline=False)
    monkeypatch.setattr(ransomware_live, "cached_get", lambda *a, **k: {"victims": [{"victim": "A", "group": "g"}, 5, None, "x"]})
    assert len(ransomware_live.fetch(offline=False)) == 1
    monkeypatch.setattr(ransomware_live, "cached_get", lambda *a, **k: [{"victim": "A"}] * 5)
    assert ransomware_live.fetch(offline=False, limit=0) == [] and len(ransomware_live.fetch(offline=False, limit=2)) == 2


def test_one_bad_record_does_not_lose_the_rest_of_the_batch():
    body = {"query_status": "ok", "data": [{"ioc": "a"}, "junk", {"ioc": None}, {"ioc": "b"}]}
    assert [i.text.split(": ")[1].split(" ")[0] for i in threatfox.parse(body)] == ["a", "b"]


def test_text_helper_bounds_and_coerces():
    assert base.text(None) == "" and base.text(5) == "5" and base.text("  hi ") == "hi" and base.text(["x"]) == ""
    assert len(base.text("x" * 99999)) == 2000 and len(base.text("x" * 99999, 10)) == 10


# ---------------- the feed cache ----------------

def test_a_damaged_cache_file_is_refetched_not_fatal(monkeypatch, tmp_path):
    import hashlib

    import requests
    monkeypatch.setattr(base, "CACHE", tmp_path)
    url = "https://example.test/feed"
    (tmp_path / (hashlib.sha1(url.encode()).hexdigest() + ".json")).write_text('{"cut": ', encoding="utf-8")

    class R:
        status_code = 200

        def raise_for_status(self): pass
        def json(self): return {"ok": True}
    monkeypatch.setattr(requests, "get", lambda *a, **k: R())
    assert base.cached_get(url) == {"ok": True}
    assert base.cached_get(url) == {"ok": True}  # and the repaired cache is valid JSON now
    assert not list(tmp_path.glob("*.tmp"))


# ---------------- CSV export ----------------

NASTY = ["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(1)", "\t=1", "\r=1", "\n=1", "  =1+1", " =1", "a,b", 'say "hi"', "line1\nline2",
         "ünï💀", "", None, "x" * 5000]


def _alert(title, **kw):
    base_row = {"item_id": "id1", "severity": "low", "score": 10, "category": "benign", "confidence": 0.5, "title": title, "source": "s",
                "actor": "a", "org": "o", "country": "c", "seen_at": "2026-11-17", "url": "u", "demo": False, "iocs": {}, "signals": []}
    base_row.update(kw)
    return base_row


@pytest.mark.parametrize("title", NASTY, ids=lambda v: repr(v)[:15])
def test_csv_export_neutralises_and_round_trips_nasty_titles(title):
    out = export.to_csv([_alert(title, org=title, actor=title)])
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == 2  # header + exactly one record, however many newlines or commas the title has
    for cell in rows[1]:
        assert not cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n", " ")) and not cell.lstrip(" ").startswith(("=", "+", "-", "@"))


def test_csv_handles_missing_optional_fields_and_odd_indicators():
    out = export.to_csv([_alert("t", iocs={"domain": ["=evil.com"], "btc": []}, signals=[{"name": "=x", "score": 1}], url=None, seen_at=None)])
    assert "'=evil.com" in out or "domain:=evil.com" in out.replace("'", "")
    assert len(list(csv.reader(io.StringIO(out)))) == 2


def test_stix_export_with_odd_dates_and_empty_lists_is_valid():
    for seen in (None, "", "garbage", "2026-13-45", "2026-11-17T25:61:61Z", "2026-11-17", "2026-11-17T10:00:00Z", 123):
        bundle = export.to_stix([_alert("t", seen_at=seen if not isinstance(seen, int) else None, iocs={"domain": ["example.com"]})])
        assert bundle["type"] == "bundle" and all("id" in o for o in bundle["objects"])
    assert export.to_stix([])["type"] == "bundle"
    json.dumps(export.to_stix([_alert("💀‮", iocs={"cve": ["CVE-2026-1"]})]))  # serialisable


# ---------------- evidence packs and the API with nasty stored text ----------------

NASTY_TITLES = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "</title><h1>x", "'; DROP TABLE alerts; --", "{{7*7}}", "${jndi:ldap://x}", "‮txt.exe",
                "a" * 3000, "💀" * 500, "\x00nul"]


@pytest.mark.parametrize("title", NASTY_TITLES, ids=lambda v: repr(v)[:15])
def test_nasty_stored_text_is_escaped_everywhere(client, title):
    text = f"Extortion group claims theft of customer records. {title}"
    pipeline.run(items=[Item(source="rss", kind="post", title=title, text=text, actor=title, org=title)], con=client.module.con())
    rows = client.get("/api/alerts", params={"limit": 500}).json()
    row = next(r for r in rows if r["title"] == title.replace("\x00", "\x00") or title in r["title"])
    page = client.get(f"/api/alerts/{row['item_id']}/evidence")
    assert page.status_code == 200
    low = page.text.lower()
    assert "<script>alert(1)</script>" not in low and "<img src=x" not in low and "</title><h1>" not in low
    assert client.get(f"/api/alerts/{row['item_id']}").status_code == 200
    csv_text = client.get("/api/export/alerts.csv").text
    assert csv_text.count("\n") >= 2
    assert client.get("/api/export/stix.json").status_code == 200


def test_enormous_stored_fields_do_not_break_listing(client):
    pipeline.run(items=[Item(source="rss", kind="post", title="T" * 100000, text="Extortion group claims theft of records " + "y" * 200000)],
                 con=client.module.con())
    assert client.get("/api/alerts?limit=5").status_code == 200
    assert client.get("/api/graph").status_code == 200


# ---------------- dates and retention ----------------

@pytest.mark.parametrize("seen", ["", "garbage", "2026-13-45", "9999-99-99", "0001-01-01", "2026-11-17T10:00:00Z", "  ", "💀"])
def test_odd_seen_at_values_never_break_pruning_or_listing(client, seen):
    con = client.module.con()
    pipeline.run(items=[Item(source="rss", kind="post", title="D", text="Extortion group claims theft of records", seen_at=seen)], con=con)
    assert isinstance(db.prune(con, "2026-01-01"), int)
    assert client.get("/api/alerts?limit=5").status_code == 200


def test_prune_keeps_demo_and_recent_items(client):
    con = client.module.con()
    before = con.execute("SELECT COUNT(*) c FROM items").fetchone()["c"]
    db.prune(con, "1999-01-01")  # nothing is older than that
    assert con.execute("SELECT COUNT(*) c FROM items").fetchone()["c"] == before


# ---------------- concurrency ----------------

def test_simultaneous_watchlist_writes_and_reads_do_not_fail(client):
    results = []

    def writer(i):
        results.append(client.post("/api/watchlist", json={"kind": "product", "value": f"product{i}"}).status_code)

    def reader():
        results.append(client.get("/api/alerts?limit=20").status_code)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)] + [threading.Thread(target=reader) for _ in range(8)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert len(results) == 16 and set(results) <= {200, 429}, results
    assert time.perf_counter() - t0 < 60
    assert len([w for w in client.get("/api/watchlist").json() if w["value"].startswith("product")]) >= 1


def test_repeated_ingest_of_the_same_items_is_idempotent(client):
    con = client.module.con()
    item = Item(source="rss", kind="post", title="Same", text="Extortion group claims theft of customer records")
    for _ in range(5):
        pipeline.run(items=[item], con=con)
    assert sum(1 for r in client.get("/api/alerts?limit=500").json() if r["title"] == "Same") == 1
