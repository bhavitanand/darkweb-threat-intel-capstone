"""Collectors against the documented shapes of the Ransomware.live PRO API and the ThreatFox API. Network is mocked."""
import pytest

from darklens import ingest
from darklens.collectors import ransomware_live as rl
from darklens.collectors import threatfox as tf
from darklens.store import db

PRO_VICTIM = {  # the fields the PRO API documents for /victims/recent
    "victim": "Example Industries Pvt Ltd", "group": "PixelLeaks", "attackdate": "2026-11-15T21:19:27.772822+00:00",
    "discovered": "2026-11-15T21:19:28.887271+00:00", "country": "IN", "activity": "Manufacturing",
    "website": "example.invalid", "screenshot": "", "infostealer": {}, "press": None,
    "id": "RXhhbXBsZUBQaXhlbA==", "permalink": "https://www.ransomware.live/id/RXhhbXBsZUBQaXhlbA==",
}


# ---- Ransomware.live ----

def test_live_mode_refuses_to_run_without_a_key(monkeypatch):
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    with pytest.raises(rl.MissingKey):
        rl.fetch(offline=False)


def test_live_mode_calls_the_pro_endpoint_with_the_key_header(monkeypatch):
    seen = {}

    def fake_get(url, headers=None, **kw):
        seen["url"], seen["headers"] = url, headers
        return [PRO_VICTIM]

    monkeypatch.setattr(rl, "cached_get", fake_get)
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "  k-123  ")
    items = rl.fetch(offline=False)
    assert seen["url"] == "https://api-pro.ransomware.live/victims/recent"
    assert seen["headers"] == {"X-API-KEY": "k-123"} and len(items) == 1


def test_pro_fields_map_to_an_item_without_a_description():
    it = rl._to_item(PRO_VICTIM)
    assert it.title == "PixelLeaks: Example Industries Pvt Ltd" and it.actor == "PixelLeaks" and it.country == "IN"
    assert it.url == PRO_VICTIM["permalink"] and it.seen_at == "2026-11-15" and it.kind == "leak_claim"
    assert "Sector: Manufacturing" in it.text and "Website: example.invalid" in it.text  # so a watched domain can match
    assert it.meta["no_redistribute"] is True and it.meta["attribution"] == "Source: Ransomware.live"


def test_legacy_fields_and_missing_values_still_work():
    it = rl._to_item({"post_title": "Old Co", "group_name": "G", "description": "Deadline: 2026-12-01", "domain": "old.invalid",
                      "activity": "Not Found", "url": "https://x"})
    assert it.title == "G: Old Co" and "Deadline: 2026-12-01" in it.text and "Sector" not in it.text
    bare = rl._to_item({})
    assert bare.title == ": " and bare.country == "" and bare.seen_at == ""


@pytest.mark.parametrize("payload", [[PRO_VICTIM], {"victims": [PRO_VICTIM]}, {"data": [PRO_VICTIM]}, {"other": 1}, []])
def test_list_and_wrapped_responses_are_accepted(monkeypatch, payload):
    monkeypatch.setattr(rl, "cached_get", lambda url, headers=None, **kw: payload)
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "k")
    expected = 1 if payload in ([PRO_VICTIM], {"victims": [PRO_VICTIM]}, {"data": [PRO_VICTIM]}) else 0
    assert len(rl.fetch(offline=False)) == expected


def test_garbage_entries_are_ignored_and_limit_applies(monkeypatch):
    monkeypatch.setattr(rl, "cached_get", lambda url, headers=None, **kw: [PRO_VICTIM, "junk", None, 5] + [PRO_VICTIM] * 10)
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "k")
    assert len(rl.fetch(offline=False, limit=3)) == 1  # limit applies before junk is filtered: [PRO, junk, None]


def test_demo_samples_are_fictional_and_shareable():
    items = rl.fetch(offline=True)
    assert items and not any(i.meta.get("no_redistribute") for i in items)


def test_ingest_skips_ransomware_live_without_a_key_and_says_why(monkeypatch, tmp_path):
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    con = db.connect(tmp_path / "c.db")
    by = {s["source"]: s for s in ingest.run_ingest(live=True, con=con)["sources"]}
    assert by["ransomware.live"]["status"] == "skipped" and "API key" in by["ransomware.live"]["note"]


# ---- CISA Known Exploited Vulnerabilities ----

from datetime import datetime, timedelta, timezone  # noqa: E402

from darklens import pipeline  # noqa: E402
from darklens.collectors import cisa_kev as kev  # noqa: E402
from darklens.collectors import urlhaus as uh  # noqa: E402
from darklens.nlp.classifier import get_classifier  # noqa: E402


def kev_entry(cve="CVE-2026-100001", days_ago=1, ransomware="Unknown", **kw):
    added = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    e = {"cveID": cve, "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Acme Gateway RCE",
         "dateAdded": added, "shortDescription": "Allows remote code execution.", "knownRansomwareCampaignUse": ransomware}
    e.update(kw)
    return e


def test_kev_offline_is_empty_and_needs_no_key():
    assert kev.fetch(offline=True) == []


def test_kev_keeps_only_recent_entries_newest_first_and_caps(monkeypatch):
    feed = {"vulnerabilities": [kev_entry("CVE-OLD", days_ago=400), kev_entry("CVE-A", 3), kev_entry("CVE-B", 1), kev_entry("CVE-C", 10)]}
    monkeypatch.setattr(kev, "cached_get", lambda url, **kw: feed)
    assert [i.meta["cve"] for i in kev.fetch(offline=False)] == ["CVE-B", "CVE-A", "CVE-C"]
    assert len(kev.fetch(offline=False, limit=2)) == 2 and len(kev.fetch(offline=False, days=5)) == 2


def test_kev_item_shape_and_ransomware_flag():
    it = kev._to_item(kev_entry(ransomware="Known"))
    assert it.kind == "advisory" and it.source == "cisa-kev" and it.title == "CVE-2026-100001: Acme Gateway"
    assert it.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-100001" and it.meta["ransomware"] is True
    assert "Known ransomware use: yes" in it.text and kev._to_item(kev_entry()).meta["ransomware"] is False


@pytest.mark.parametrize("bad", [None, [], "x", {"vulnerabilities": "nope"}, {"other": 1}])
def test_kev_rejects_an_unexpected_answer(monkeypatch, bad):
    monkeypatch.setattr(kev, "cached_get", lambda url, **kw: bad)
    with pytest.raises(RuntimeError, match="Unexpected"):
        kev.fetch(offline=False)


def test_kev_skips_junk_entries(monkeypatch):
    monkeypatch.setattr(kev, "cached_get", lambda url, **kw: {"vulnerabilities": [kev_entry(), "junk", None, {"dateAdded": "2999-01-01"}]})
    assert len(kev.fetch(offline=False)) == 1  # an entry with no cveID is dropped


def test_an_exploited_flaw_is_low_but_a_ransomware_one_is_medium_and_a_watched_name_is_a_real_alert():
    clf = get_classifier()
    plain = pipeline.analyse(kev._to_item(kev_entry()), [], [], clf)
    ransom = pipeline.analyse(kev._to_item(kev_entry(ransomware="Known")), [], [], clf)
    assert plain.category == "known_exploited" and plain.severity == "low"
    assert ransom.severity == "medium" and ransom.score > plain.score
    assert [s.name for s in plain.signals] == ["Exploited in the wild"] and "cve" in plain.iocs
    watched = pipeline.analyse(kev._to_item(kev_entry(vendorProject="Acme", shortDescription="See acme.example")), ["acme.example"], [], clf)
    assert watched.severity in ("high", "critical")


# ---- URLhaus ----

UH_ROW = {"id": "1", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/", "url": "http://203.0.113.9/a/b.exe", "url_status": "online",
          "host": "203.0.113.9", "date_added": "2026-11-15 09:02:05 UTC", "threat": "malware_download", "tags": ["elf", "mirai"]}


def test_urlhaus_offline_is_empty_and_live_needs_a_key(monkeypatch):
    assert uh.fetch(offline=True) == []
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(uh.MissingKey):
        uh.fetch(offline=False)


def test_urlhaus_parses_the_documented_response_and_keeps_status_out_of_the_id():
    online = uh.parse({"query_status": "ok", "urls": [UH_ROW]})[0]
    offline = uh.parse({"query_status": "ok", "urls": [{**UH_ROW, "url_status": "offline"}]})[0]
    assert online.kind == "ioc" and online.title == "URLhaus elf download link" and online.seen_at == "2026-11-15"
    assert online.url == UH_ROW["urlhaus_reference"] and "203.0.113.9" in online.text
    assert online.meta["confidence"] == 80 and offline.meta["confidence"] == 40
    assert online.id == offline.id  # the same address does not become a new item when its status flips


@pytest.mark.parametrize("body,expected", [
    ({"query_status": "no_results"}, 0), ({"query_status": "ok"}, 0), ({"query_status": "ok", "urls": "x"}, 0),
    ({"query_status": "ok", "urls": [UH_ROW, {"id": "2"}, "junk", None]}, 1),
    ({"query_status": "ok", "urls": [{**UH_ROW, "tags": None}]}, 1),
])
def test_urlhaus_tolerates_every_shape(body, expected):
    assert len(uh.parse(body)) == expected


@pytest.mark.parametrize("status", ["http_get_expected", None, "weird"])
def test_urlhaus_errors_are_raised(status):
    with pytest.raises(RuntimeError, match="URLhaus answered"):
        uh.parse({"query_status": status})


def test_urlhaus_live_sends_the_key_and_clamps_the_limit(monkeypatch):
    import requests
    seen = {}

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"query_status": "ok", "urls": [UH_ROW]}

    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=0: seen.update(url=url, headers=headers) or Reply())
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    assert len(uh.fetch(offline=False, limit=99999)) == 1
    assert seen["url"].endswith("/v1/urls/recent/limit/1000/") and seen["headers"]["Auth-Key"] == "k"
    uh.fetch(offline=False, limit=0)
    assert seen["url"].endswith("/limit/1/")


def test_a_lone_malware_link_stays_low_but_your_own_domain_in_one_is_an_alert():
    clf = get_classifier()
    row = {**UH_ROW, "url": "http://acme.example/wp/shell.php", "host": "acme.example"}
    item = uh.parse({"query_status": "ok", "urls": [row]})[0]
    assert pipeline.analyse(item, [], [], clf).severity == "low"
    assert pipeline.analyse(item, ["acme.example"], [], clf).severity in ("high", "critical")


# ---- ThreatFox ----

OK_ROW = {"id": "41", "ioc": "gaga.com", "threat_type": "botnet_cc", "ioc_type": "domain", "malware": "win.dridex",
          "malware_printable": "Dridex", "confidence_level": 50, "first_seen": "2020-12-08 13:36:27 UTC"}


def test_threatfox_parses_the_documented_response():
    items = tf.parse({"query_status": "ok", "data": [OK_ROW]})
    assert len(items) == 1 and items[0].title == "Dridex domain" and items[0].seen_at == "2020-12-08"
    assert items[0].meta["confidence"] == 50 and "gaga.com" in items[0].text


@pytest.mark.parametrize("body,expected", [
    ({"query_status": "no_result", "data": "Your search did not yield any results"}, 0),
    ({"query_status": "ok", "data": "not a list"}, 0),
    ({"query_status": "ok", "data": None}, 0),
    ({"query_status": "ok", "data": []}, 0),
    ({"query_status": "ok", "data": [OK_ROW, {"id": "2"}, "junk", None]}, 1),  # entries without an ioc are dropped
])
def test_threatfox_tolerates_every_documented_shape(body, expected):
    assert len(tf.parse(body)) == expected


@pytest.mark.parametrize("status", ["unauthorized", "illegal_days", None, "weird"])
def test_threatfox_errors_are_raised_not_silently_empty(status):
    with pytest.raises(RuntimeError, match="ThreatFox answered"):
        tf.parse({"query_status": status})


def test_threatfox_live_needs_a_key_sends_it_and_clamps_days(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(tf.MissingKey):
        tf.fetch(offline=False)
    sent = {}

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"query_status": "ok", "data": [OK_ROW]}

    import requests
    monkeypatch.setattr(requests, "post", lambda url, json=None, headers=None, timeout=0: sent.update(url=url, json=json, headers=headers) or Reply())
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "abc")
    assert len(tf.fetch(offline=False, days=99)) == 1
    assert sent["json"] == {"query": "get_iocs", "days": 7} and sent["headers"]["Auth-Key"] == "abc"
    tf.fetch(offline=False, days=0)
    assert sent["json"]["days"] == 1
