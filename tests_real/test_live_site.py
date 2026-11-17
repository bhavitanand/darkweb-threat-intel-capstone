"""Smoke test of the DEPLOYED product on its real, live feeds.

Run:  python -m pytest tests_real/test_live_site.py -q
Set DARKLENS_API to test another deployment. Skipped when the network is not reachable. The free host sleeps when idle,
so the first request can take up to a minute.
"""
import json
import os
import urllib.error
import urllib.request

import pytest

API = os.environ.get("DARKLENS_API", "https://darklens-capstone.onrender.com").rstrip("/")


def get(path, timeout=90):
    req = urllib.request.Request(API + path, headers={"User-Agent": "darklens-smoke-test"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read()


@pytest.fixture(scope="module", autouse=True)
def _online():
    try:
        get("/api/health")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"deployment not reachable: {e}")


def test_health_and_version():
    s, _, body = get("/api/health")
    assert s == 200 and json.loads(body)["ok"] is True


def test_live_feeds_are_flowing_and_numbers_agree():
    stats = json.loads(get("/api/stats")[2])
    assert stats["real_alerts"] > 0, "no real alerts: are the live feeds running?"
    assert stats["alerts"] == stats["real_alerts"] + stats["demo_alerts"]
    assert sum(stats["by_severity"].values()) == stats["alerts"]
    status = json.loads(get("/api/ingest/status")[2])
    assert status, "ingest status empty"


def test_alert_list_detail_evidence_and_exports_on_real_alerts():
    rows = json.loads(get("/api/alerts?limit=20")[2])
    assert rows and rows == sorted(rows, key=lambda r: (-r["score"], r["item_id"]))
    real = next((r for r in rows if not r["demo"]), rows[0])
    d = json.loads(get(f"/api/alerts/{real['item_id']}")[2])
    assert d["signals"] and 0 <= d["score"] <= 100
    s, _, page = get(f"/api/alerts/{real['item_id']}/evidence")
    assert s == 200 and b"<script" not in page.lower()
    for export in ("alerts.csv", "stix.json"):
        assert get(f"/api/export/{export}")[0] == 200


def test_restricted_source_text_is_not_exposed():
    rows = json.loads(get("/api/alerts?limit=300")[2])
    leaked = [r["item_id"] for r in rows if r.get("restricted") and r.get("text")]
    assert not leaked, leaked[:3]


def test_paging_headers_when_the_deployment_has_them():
    s, headers, body = get("/api/alerts?limit=5&offset=5")
    total = {k.lower(): v for k, v in headers.items()}.get("x-total-count")
    if total is None:
        pytest.skip("this deployment predates server-side paging")
    assert len(json.loads(body)) == 5 and int(total) >= 10


def test_analyse_endpoint_on_real_headlines():
    def analyse(text):
        req = urllib.request.Request(API + "/api/analyse", data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": "darklens-smoke-test"})
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read())
    ordinary = analyse("UK economy grows at fastest rate for more than two years")
    assert ordinary["score"] == 0 or ordinary["severity"] == "low"
    threat = analyse("Extortion Group Claims Theft of Nearly One Billion Expedia Traveler Records")
    assert threat["score"] > 0 and threat["category"] == "ransomware_leak"
