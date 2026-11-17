"""The keyless live sources (breaches, phishing pages, botnet servers, security news) and exploit-probability scoring."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import ingest, pipeline
from darklens.collectors import base, cisa_kev, feodo, hibp, news, openphish
from darklens.labelling import sources
from darklens.models import Item
from darklens.nlp.classifier import get_classifier

CLF = get_classifier()


def days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%dT00:00:00Z")


@pytest.fixture
def client(monkeypatch):
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


# ---------------- Have I Been Pwned ----------------

def breach(name="Acme", added=5, **kw):
    b = {"Name": name, "Title": name, "AddedDate": days_ago(added), "PwnCount": 1000, "IsVerified": True, "DataClasses": ["Email addresses", "Passwords"],
         "Description": f'In 2026, <a href="https://x">{name}</a> suffered a data breach &amp; the data was posted online.'}
    b.update(kw)
    return b


def test_breach_item_is_cleaned_and_attributed():
    it = hibp._to_item(breach("Acme"))
    assert it.kind == "breach_report" and it.source == "haveibeenpwned" and it.org == "Acme"
    assert "<a" not in it.text and "&amp;" not in it.text and "Data exposed: Email addresses, Passwords." in it.text
    assert "CC BY 4.0" in it.meta["attribution"] and it.meta.get("no_redistribute") is None  # CC BY: may be shown and exported


def test_fetch_filters_sorts_and_limits(monkeypatch):
    data = [breach("Old", 400), breach("New", 1), breach("Mid", 20), breach("Spam", 2, IsSpamList=True), breach("Fake", 2, IsFabricated=True),
            breach("Tiny", 2, Description="x"), "junk", None, {"Name": "NoDate"}]
    monkeypatch.setattr(hibp, "cached_get", lambda *a, **k: data)
    assert [i.org for i in hibp.fetch(offline=False)] == ["New", "Mid"]
    assert [i.org for i in hibp.fetch(offline=False, limit=1)] == ["New"]
    assert hibp.fetch(offline=False, limit=0) == [] and hibp.fetch(offline=True) == []


@pytest.mark.parametrize("bad", [{}, "text", None, 5])
def test_fetch_rejects_a_non_list_answer(monkeypatch, bad):
    monkeypatch.setattr(hibp, "cached_get", lambda *a, **k: bad)
    with pytest.raises(RuntimeError):
        hibp.fetch(offline=False)


@pytest.mark.parametrize("value", [None, 0, [], {}, "x" * 9000, float("nan"), True])
def test_breach_with_odd_fields_does_not_crash(value):
    it = hibp._to_item({"Name": value, "Title": value, "Description": value, "DataClasses": value, "AddedDate": value, "PwnCount": value})
    assert isinstance(it.text, str) and isinstance(it.title, str) and len(it.text) < 3000


def test_a_listed_breach_is_a_credential_dump_with_evidence_and_never_uncertain():
    it = hibp._to_item(breach("Acme"))
    a = pipeline.analyse(it, [], [], CLF)
    assert a.category == "credential_dump" and a.score > 40
    assert any(s.name == "Listed as a real data breach" for s in a.signals)
    vague = Item(source="haveibeenpwned", kind="breach_report", title="V: data breach", text="Something happened with some accounts at an unnamed place", org="V")
    b = pipeline.analyse(vague, [], [], CLF)
    assert b.category == "credential_dump" and b.score > 0  # the source says it is a breach, so a vague text is still an alert


# ---------------- OpenPhish ----------------

def test_openphish_parses_dedupes_and_skips_junk():
    body = "\n".join(["http://evil.example/login", "https://evil.example/login", "http://evil.example/login", "not a url", "", "ftp://x.test/a",
                      "http://[::1", "http://a.test/" + "x" * 600, "https://ok.test/a?b=1&c=2", "  https://spaced.test/z  "])
    got = openphish.parse(body)
    assert [i.text.split(": ", 1)[1] for i in got] == ["http://evil.example/login", "https://evil.example/login", "https://ok.test/a?b=1&c=2", "https://spaced.test/z"]
    assert all(i.kind == "ioc" and i.meta["confidence"] == 85 and "OpenPhish" in i.meta["attribution"] for i in got)


def test_openphish_limit_and_offline_and_empty():
    body = "\n".join(f"http://p{i}.test/x" for i in range(50))
    assert len(openphish.parse(body, limit=7)) == 7 and openphish.parse(body, limit=0) == []
    assert openphish.parse("") == [] and openphish.parse(None) == [] and openphish.fetch(offline=True) == []


def test_a_lone_phishing_page_stays_low_and_is_about_you_when_watched():
    it = openphish.parse("http://login.acme-bank.example/verify")[0]
    assert pipeline.analyse(it, [], [], CLF).severity == "low"
    mine = pipeline.analyse(it, ["acme-bank.example"], [], CLF)
    assert mine.severity in ("high", "critical")


# ---------------- Feodo ----------------

def feodo_row(ip="1.2.3.4", last="2026-11-01", status="offline", **kw):
    r = {"ip_address": ip, "port": 443, "status": status, "malware": "QakBot", "country": "US", "first_seen": "2026-01-01 00:00:00", "last_online": last}
    r.update(kw)
    return r


def test_feodo_filters_old_sorts_and_scores_online_higher():
    data = [feodo_row("1.1.1.1", "2020-01-01"), feodo_row("2.2.2.2", "2026-10-01", "offline"), feodo_row("3.3.3.3", "2026-11-10", "online"), "junk", {"ip_address": ""}]
    got = feodo.parse(data, days=100000)
    assert [i.text.split(": ")[1].split(" ")[0] for i in got] == ["3.3.3.3:443", "2.2.2.2:443", "1.1.1.1:443"]
    assert got[0].meta["confidence"] == 90 and got[1].meta["confidence"] == 60
    assert [i.actor for i in feodo.parse(data, days=100000, limit=1)] == ["QakBot"]


@pytest.mark.parametrize("bad", [{}, "x", None, 3])
def test_feodo_rejects_non_list(bad):
    with pytest.raises(RuntimeError):
        feodo.parse(bad)


@pytest.mark.parametrize("value", [None, 0, [], {}, "x" * 999, True, float("nan")])
def test_feodo_odd_fields_do_not_crash(value):
    out = feodo.parse([feodo_row(port=value, malware=value, status=value, country=value, last_online="2026-11-01")], days=100000)
    assert isinstance(out[0].text, str)


# ---------------- security news ----------------

RSS = b"""<?xml version="1.0"?><rss><channel>
<item><title>Hackers stole data from Acme</title><description>&lt;p&gt;Attackers breached Acme and posted customer records.&lt;/p&gt;</description>
<link>https://news.example/a</link><pubDate>Mon, 16 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>No date or link here</title><description>plain</description></item>
<item><title>Bad link</title><link>javascript:alert(1)</link><pubDate>garbage</pubDate></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Atom story</title><summary>s</summary>
<link href="https://atom.example/x"/><updated>2026-11-15T08:00:00Z</updated></entry></feed>"""


def test_feed_entries_carry_title_link_and_date():
    rss = sources.parse_feed(RSS, "n", "security")
    assert rss[0]["title"] == "Hackers stole data from Acme" and rss[0]["link"] == "https://news.example/a" and "2026" in rss[0]["date"]
    assert sources.parse_feed(ATOM, "a", "security")[0]["link"] == "https://atom.example/x"


def test_news_items_are_hidden_text_with_safe_links_and_dates():
    items = news.to_items(sources.parse_feed(RSS, "krebsonsecurity", "security"), "krebsonsecurity")
    assert items[0].seen_at == "2026-11-16" and items[0].url == "https://news.example/a" and items[0].meta["no_redistribute"] is True
    assert items[1].url == "" and items[1].seen_at == datetime.now(timezone.utc).strftime("%Y-%m-%d")  # undated: today, so it can expire
    assert items[2].url == "" and items[2].seen_at == datetime.now(timezone.utc).strftime("%Y-%m-%d")  # javascript: link refused, bad date -> today
    assert len(news.to_items(sources.parse_feed(RSS, "x", "security"), "x", per_feed=1)) == 1 and news.to_items([], "x") == []


@pytest.mark.parametrize("raw,want", [("Mon, 16 Nov 2026 10:00:00 GMT", "2026-11-16"), ("2026-11-15T08:00:00Z", "2026-11-15"), ("2026-11-15", "2026-11-15"),
                                      ("garbage", ""), ("", ""), ("2026-13-45", "2026-13-45"), (None, "")])
def test_feed_dates_are_normalised_or_blank(raw, want):
    got = news._day(raw)
    assert got == want or (raw == "2026-13-45" and got in ("", "2026-13-45"))


def test_news_fetch_survives_a_failing_feed_and_fails_only_when_all_fail(monkeypatch):
    calls = []

    def one(feed):
        calls.append(feed[0])
        if feed[0] == "bleepingcomputer":
            raise ConnectionError("down")
        return [Item(source=feed[0], kind="post", title="t", text="t")]
    monkeypatch.setattr(news, "_one", one)
    got = news.fetch(offline=False)
    assert got and "bleepingcomputer" in calls and all(i.source != "bleepingcomputer" for i in got)
    monkeypatch.setattr(news, "_one", lambda feed: (_ for _ in ()).throw(ConnectionError("down")))
    with pytest.raises(RuntimeError):
        news.fetch(offline=False)
    assert news.fetch(offline=True) == []


def test_hostile_feed_xml_yields_nothing():
    for bad in (b'<!DOCTYPE x [<!ENTITY a "b">]><rss/>', b"not xml", b"", b"<rss>" + b"x" * 3_000_000):
        assert sources.parse_feed(bad, "x", "security") == []


def test_real_breach_news_becomes_an_alert_and_ordinary_news_does_not():
    breach_news = Item(source="therecord", kind="post", title="Uber notifies drivers of data breach", text="Uber notifies drivers of data breach affecting nearly 150,000 people after attackers stole their data.")
    ordinary = Item(source="therecord", kind="post", title="UK economy grows", text="UK economy grows at fastest rate for more than two years, official figures show.")
    assert pipeline.analyse(breach_news, [], [], CLF).score > 0 and pipeline.analyse(ordinary, [], [], CLF).score == 0


def test_news_text_is_never_returned_searched_or_exported(client):
    secret = "zebrafishcanary"
    it = news.to_items([{"title": "Extortion group claims theft of customer records", "text": f"Extortion group claims theft of customer records. {secret}", "link": "https://n.example/1", "date": ""}], "therecord")[0]
    pipeline.run(items=[it], con=client.module.con())
    rows = client.get("/api/alerts", params={"q": "extortion group"}).json()
    row = next(r for r in rows if r["source"] == "therecord")
    assert row["text"] == "" and row["restricted"] is True and row["url"] == "https://n.example/1"
    assert client.get("/api/alerts", params={"q": secret}).json() == []
    assert secret not in client.get("/api/export/alerts.csv").text and "therecord" not in client.get("/api/export/alerts.csv").text
    assert secret not in client.get("/api/export/stix.json").text


# ---------------- EPSS (exploit probability) ----------------

def advisory(epss=None, ransomware=False):
    meta = {"cve": "CVE-2026-1", "ransomware": ransomware}
    if epss is not None:
        meta["epss"] = epss
    return Item(source="cisa-kev", kind="advisory", title="CVE-2026-1: Acme Widget", text="CVE-2026-1: flaw. Affects Acme Widget.", meta=meta)


def test_a_likely_to_be_exploited_flaw_scores_above_an_unlikely_one():
    base_score = pipeline.analyse(advisory(), [], [], CLF).score
    assert pipeline.analyse(advisory(0.01), [], [], CLF).score == base_score  # below the 5% floor: no signal
    high = pipeline.analyse(advisory(0.97), [], [], CLF)
    assert high.score > base_score and any("EPSS" in s.name for s in high.signals) and "97%" in [s.why for s in high.signals if "EPSS" in s.name][0]


@pytest.mark.parametrize("bad", ["0.9", None, True, [], {}, float("nan"), -1, 5])
def test_odd_epss_values_never_crash_and_stay_in_range(bad):
    a = pipeline.analyse(advisory(bad), [], [], CLF)
    assert 0 <= a.score <= 100


def test_epss_scores_parses_batches_and_tolerates_failures(monkeypatch):
    seen = []

    def fake(url, **k):
        seen.append(url)
        if len(seen) == 2:
            raise ConnectionError("down")
        return {"data": [{"cve": "CVE-2026-1", "epss": "0.5", "percentile": "0.9"}, {"cve": "bad"}, "junk", {"cve": "CVE-2026-2", "epss": "x", "percentile": "1"}]}
    monkeypatch.setattr(cisa_kev, "cached_get", fake)
    out = cisa_kev.epss_scores([f"CVE-2026-{i}" for i in range(250)])
    assert out == {"CVE-2026-1": (0.5, 0.9)} and len(seen) == 3  # three batches of up to 100; the failed one is skipped
    monkeypatch.setattr(cisa_kev, "cached_get", lambda *a, **k: "not a dict")
    assert cisa_kev.epss_scores(["CVE-2026-1"]) == {} and cisa_kev.epss_scores([]) == {}


def test_kev_fetch_attaches_epss_when_available(monkeypatch):
    vulns = {"vulnerabilities": [{"cveID": "CVE-2026-9", "vendorProject": "V", "product": "P", "dateAdded": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "vulnerabilityName": "n"}]}
    monkeypatch.setattr(cisa_kev, "cached_get", lambda url, **k: vulns if "cisa.gov" in url else {"data": [{"cve": "CVE-2026-9", "epss": "0.8", "percentile": "0.95"}]})
    it = cisa_kev.fetch(offline=False)[0]
    assert it.meta["epss"] == 0.8 and it.meta["epss_percentile"] == 0.95


# ---------------- all of it through a live collection ----------------

def test_a_live_run_collects_every_keyless_source_and_reports_each(monkeypatch, tmp_path):
    from darklens.store import db
    con = db.connect(tmp_path / "live.db")
    monkeypatch.setattr(hibp, "fetch", lambda offline=True, **k: [hibp._to_item(breach("Acme"))])
    monkeypatch.setattr(openphish, "fetch", lambda offline=True, **k: openphish.parse("http://evil.example/x"))
    monkeypatch.setattr(feodo, "fetch", lambda offline=True, **k: [])
    monkeypatch.setattr(news, "fetch", lambda offline=True, **k: (_ for _ in ()).throw(RuntimeError("All 3 news feeds failed.")))
    monkeypatch.setattr(ingest.cisa_kev, "fetch", lambda offline=True, **k: [advisory(0.9)])
    st = ingest.run_ingest(live=True, con=con)
    by = {s["source"]: s for s in st["sources"]}
    assert by["haveibeenpwned"]["status"] == "ok" and by["haveibeenpwned"]["items"] == 1
    assert by["openphish"]["items"] == 1 and by["feodo"]["status"] == "ok" and by["cisa-kev"]["items"] == 1
    assert by["security-news"]["status"] == "error" and "news feeds failed" in by["security-news"]["note"]  # one failing source does not stop the rest
    assert by["ransomware.live"]["status"] == "skipped" and st["alerts"] >= 3
    assert ingest.status(con)["live_ready"] is True  # live without a single key
