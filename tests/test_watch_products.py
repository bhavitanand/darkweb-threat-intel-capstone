"""Watching software and vendors: a flaw or attack on something you run is about you."""
import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import pipeline
from darklens.models import Item
from darklens.nlp.classifier import get_classifier

CLF = get_classifier()


@pytest.fixture
def client(monkeypatch):
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


def run(text, products, kind="post", meta=None, title=""):
    it = Item(source="rss", kind=kind, title=title, text=text, meta=meta or {})
    return pipeline.analyse(it, [], [], CLF, products)


def names(a):
    return [s.name for s in a.signals]


def test_an_attack_on_a_product_you_run_is_high_not_low():
    text = "Attackers exploit a ScreenConnect flaw to compromise managed service providers"
    without = run(text, [])
    with_it = run(text, ["screenconnect"])
    assert "Watchlist product match" in names(with_it)
    assert with_it.score > without.score and with_it.severity in ("high", "critical")


def test_a_cisa_exploited_flaw_in_your_vendor_becomes_high():
    meta = {"cve": "CVE-2026-0001"}
    a0 = run("Vendor Fortinet product FortiOS", [], kind="advisory", meta=meta, title="Fortinet FortiOS flaw")
    a1 = run("Vendor Fortinet product FortiOS", ["fortinet"], kind="advisory", meta=meta, title="Fortinet FortiOS flaw")
    assert a0.severity == "low" and a1.severity in ("high", "critical")
    assert "Watchlist product match" in names(a1)


def test_a_routine_patch_story_is_medium_not_an_emergency():
    a = run("Microsoft fixes a bug in Windows Paint and ships the November security updates", ["microsoft"])
    assert "Watchlist product flaw" in names(a) and "Watchlist product match" not in names(a)
    assert a.severity in ("low", "medium")


def test_a_passing_mention_is_only_a_low_hint():
    a = run("Fortinet announces a new office and a partnership with a university", ["fortinet"])
    assert "Watchlist product match" not in names(a)
    assert a.severity in ("low", "medium")


def test_matching_is_by_whole_word_so_short_names_do_not_fire_inside_other_words():
    a = run("The attack used a bespoke loader named nextgen against a hospital", ["gen"])
    assert "Watchlist product match" not in names(a) and "Watched product mentioned" not in names(a)
    b = run("A new vulnerability in Nextcloud lets attackers read files", ["next"])
    assert "Watchlist product match" not in names(b)


def test_other_products_do_not_match():
    a = run("Attackers exploit a ScreenConnect flaw", ["fortinet"])
    assert "Watchlist product match" not in names(a)


def test_no_products_behaves_exactly_as_before():
    text = "Extortion Group Claims Theft of Nearly One Billion Expedia Traveler Records"
    assert run(text, []).score == pipeline.analyse(Item(source="rss", kind="post", title="", text=text), [], [], CLF).score


@pytest.mark.parametrize("value,ok", [("screenconnect", True), ("N-able N-central", True), ("  Fortinet ", True),
                                      ("ab", False), ("<script>", False), ("a" * 80, False), ("", False)])
def test_api_validates_product_names(client, value, ok):
    r = client.post("/api/watchlist", json={"kind": "product", "value": value})
    assert (r.status_code == 200) == ok


def test_api_stores_product_lowercased_and_rescoring_uses_it(client):
    con = client.module.con()
    live = Item(source="rss", kind="post", title="Exploited", text="An extortion group claims theft of customer records after attackers exploit a ScreenConnect flaw")
    pipeline.run(items=[live], con=con)
    before = next(r for r in client.get("/api/alerts").json() if r["title"] == "Exploited")
    r = client.post("/api/watchlist", json={"kind": "product", "value": "  ScreenConnect "})
    assert {"kind": "product", "value": "screenconnect"} in r.json()
    after = next(x for x in client.get("/api/alerts").json() if x["title"] == "Exploited")
    assert after["score"] > before["score"] and any(s["name"] == "Watchlist product match" for s in after["signals"])


def test_adding_one_entry_rescores_only_items_that_mention_it(client):
    con = client.module.con()
    mention = Item(source="rss", kind="post", title="Hit", text="An extortion group claims theft of customer records via a Fortinet flaw")
    other = Item(source="rss", kind="post", title="Miss", text="An extortion group claims theft of customer records at a hospital")
    pipeline.run(items=[mention, other], con=con)
    scores = lambda: {r["title"]: r["score"] for r in client.get("/api/alerts?limit=5000").json()}  # noqa: E731
    before = scores()
    calls = []
    real = pipeline.rescore
    import darklens.api.app as app_module
    app_module.pipeline.rescore = lambda c, contains=None: (calls.append(contains), real(c, contains=contains))[1]
    try:
        assert client.post("/api/watchlist", json={"kind": "product", "value": "fortinet"}).status_code == 200
    finally:
        app_module.pipeline.rescore = real
    after = scores()
    assert calls == ["fortinet"]
    assert after["Hit"] > before["Hit"] and after["Miss"] == before["Miss"]


def test_the_shared_watchlist_is_capped(client, monkeypatch):
    monkeypatch.setattr(client.module, "WATCHLIST_MAX", 3)
    for name in ("alpha", "bravo", "charlie"):
        assert client.post("/api/watchlist", json={"kind": "product", "value": name}).status_code == 200
    r = client.post("/api/watchlist", json={"kind": "product", "value": "delta"})
    assert r.status_code == 400 and "full" in r.json()["detail"]
    assert client.post("/api/watchlist", json={"kind": "product", "value": "alpha"}).status_code == 200  # an existing one is fine


def test_check_a_post_uses_the_software_watchlist(client):
    text = "Attackers exploit a ScreenConnect flaw to compromise managed service providers"
    plain = client.post("/api/analyse", json={"text": text, "title": ""}).json()
    assert client.post("/api/watchlist", json={"kind": "product", "value": "screenconnect"}).status_code == 200
    watched = client.post("/api/analyse", json={"text": text, "title": ""}).json()
    assert watched["score"] > plain["score"] and any(s["name"] == "Watchlist product match" for s in watched["signals"])
