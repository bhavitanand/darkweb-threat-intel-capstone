import os
import tempfile

os.environ["DARKLENS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")

import pytest

from darklens import pipeline
from darklens.breach import hibp
from darklens.crawler import tor
from darklens.evidence import build_pack
from darklens.extract.iocs import extract_iocs, valid_btc
from darklens.graph import entities
from darklens.models import Item
from darklens.rules.engine import load_rules, run_rules
from darklens.scoring import noisy_or, severity
from darklens.store import db


def test_ioc_extraction_validates_wallets():
    t = "pay 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 not 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"
    out = extract_iocs(t)
    assert out["btc"] == ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"]
    assert valid_btc("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")


def test_defang_and_private_ip_filter():
    out = extract_iocs("hxxp://bad[.]site/a 10.0.0.5 8.8.8.8 evil[.]com")
    assert "http://bad.site/a" in out["url"]
    assert out["ipv4"] == ["8.8.8.8"]
    assert "evil.com" in out["domain"]


def test_file_names_are_not_domains():
    assert "domain" not in extract_iocs("dropper payload.exe and report.pdf")


def test_rules_load_and_fire():
    assert len(load_rules()) >= 20
    names = [s.name for _, s in run_rules("Selling 0day RCE for Exchange, price 2 XMR")]
    assert any("Zero-day" in n for n in names)


def test_noisy_or_properties():
    assert noisy_or([]) == 0
    assert noisy_or([50]) == 50
    assert noisy_or([50, 50]) == 75
    assert noisy_or([90, 90]) > noisy_or([90])
    assert severity(90) == "critical" and severity(10) == "low"


def test_pwned_passwords_k_anonymity():
    prefix, suffix = hibp.range_query_parts("password")
    assert prefix == "5BAA6" and len(suffix) == 35
    body = f"{suffix}:9999\nABCDEF:0"
    assert hibp.parse_range_response(body, suffix) == 9999


def test_credential_exposure_never_returns_plaintext():
    hits = hibp.credential_exposure("a@corp.example:Secret123 b@other.com:zzz999", ["corp.example"])
    assert len(hits) == 1 and "Secret123" not in str(hits)
    assert "Secret123" not in hibp.mask_combolist("a@corp.example:Secret123")


def test_crawler_refuses_unlisted_hosts():
    with pytest.raises(tor.CrawlRefused):
        tor.crawl(["http://exampleexampleexample.onion/"], live=False, allow={"allowed.onion"})
    assert tor.crawl(["http://allowed.onion/x"], live=False, allow={"allowed.onion"}) == []


def test_html_to_text_strips_scripts():
    assert "evil" not in tor.html_to_text("<script>evil()</script><p>hello</p>")


def test_pipeline_watchlist_boosts_and_masks_passwords():
    con = db.connect()
    db.watch_add(con, "domain", "granite-bank.example")
    r = pipeline.run(offline=True, con=con)
    assert r["alerts"] > 5
    top = con.execute("SELECT a.score, i.text FROM alerts a JOIN items i ON i.id=a.item_id ORDER BY a.score DESC").fetchone()
    assert top["score"] >= 95 and "Winter2026" not in top["text"]


def test_actor_linking_via_shared_wallet():
    rows = [
        {"id": "1", "actor": "a", "iocs": {"btc": ["W1"]}}, {"id": "2", "actor": "b", "iocs": {"btc": ["W1"]}},
        {"id": "3", "actor": "c", "iocs": {"btc": ["W2"]}},
    ]
    linked = entities.linked_actors(entities.build_graph(rows))
    assert len(linked) == 1 and linked[0]["actors"] == ["actor:a", "actor:b"]


def test_evidence_pack_hash_changes_with_data():
    a = {"title": "t", "score": 1, "signals": [], "iocs": {}}
    _, h1 = build_pack(a)
    _, h2 = build_pack({**a, "score": 2})
    assert h1 != h2


def test_hybrid_beats_each_component_on_heldout_templates():
    from darklens.nlp.classifier import evaluate
    r = evaluate()
    assert r["hybrid"] >= max(r["rules"], r["ml"])
    assert r["hybrid"] > 0.75
