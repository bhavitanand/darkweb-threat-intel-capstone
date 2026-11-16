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
