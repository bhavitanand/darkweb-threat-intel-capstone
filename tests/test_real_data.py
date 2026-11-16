"""Behaviour on real-format data, and the tools that measure accuracy on data that is not synthetic."""
import csv

import pytest

from darklens import pipeline
from darklens.models import Item
from darklens.nlp import realeval
from darklens.nlp.classifier import get_classifier

# Same shape as a live Ransomware.live claim (templated description), with an invented organisation.
CLAIM_TEXT = ("Example Industries Pvt Ltd (example.invalid) was claimed by PixelLeaks. This disclosure concerns a verified "
              "set of records from an organization in the manufacturing sector. The material scheduled for publication "
              "comprises a set of business records, including operational material.\nDeadline: 2026-11-19 20:15 UTC")
BARE_CLAIM = "Apex was claimed by qilin."


def claim(text=CLAIM_TEXT, title="PixelLeaks: Example Industries"):
    return Item(source="ransomware.live", kind="leak_claim", title=title, text=text, actor="PixelLeaks")


def test_a_real_format_claim_is_recognised_and_not_low():
    a = pipeline.analyse(claim(), [], [], get_classifier())
    assert a.category == "ransomware_leak" and a.confidence >= 0.9
    assert a.severity in ("high", "critical")
    names = [s.name for s in a.signals]
    assert "Listed on a leak-site tracker" in names and any(n.startswith("DL-RAN-001") for n in names)


def test_even_a_bare_claim_with_no_description_is_at_least_medium():
    a = pipeline.analyse(claim(BARE_CLAIM, "qilin: Apex"), [], [], get_classifier())
    assert a.category == "ransomware_leak" and a.severity in ("medium", "high")


def test_the_source_decides_the_category_over_the_text_model():
    """The text model called some bare claims 'malware_sale'. The tracker is the better authority."""
    a = pipeline.analyse(claim("netrunner claimed F***** G****** C********** C***", "netrunner: F*** G***"), [], [], get_classifier())
    assert a.category == "ransomware_leak"


def test_ordinary_posts_do_not_get_the_tracker_signal():
    a = pipeline.analyse(Item(source="forum", kind="post", title="Hi", text="ExampleLocker leak tracker thread, nothing here"),
                         [], [], get_classifier())
    assert "Listed on a leak-site tracker" not in [s.name for s in a.signals]


def test_a_watchlist_hit_on_a_real_claim_outranks_a_plain_claim():
    plain = pipeline.analyse(claim(), [], [], get_classifier())
    about_us = pipeline.analyse(claim(), ["example.invalid"], [], get_classifier())
    assert about_us.score > plain.score and about_us.severity == "critical"


# ---- indicator feed (ThreatFox) ----

def ioc(text="Dridex indicator (botnet_cc): evil.example confidence 100", confidence=100):
    return Item(source="threatfox", kind="ioc", title="Dridex domain", text=text, actor="Dridex",
                meta={"ioc_type": "domain", "confidence": confidence})


@pytest.mark.parametrize("confidence", [0, 50, 75, 100])
def test_a_lone_feed_indicator_stays_low_whatever_its_confidence(confidence):
    a = pipeline.analyse(ioc(confidence=confidence), [], [], get_classifier())
    assert a.category == "ioc_feed" and a.severity == "low" and a.score < 40


def test_a_feed_indicator_for_your_domain_becomes_a_real_alert():
    """The thing that makes an indicator matter is that it is about you."""
    plain = pipeline.analyse(ioc(), [], [], get_classifier())
    mine = pipeline.analyse(ioc(), ["evil.example"], [], get_classifier())
    assert mine.score > plain.score and mine.severity in ("high", "critical")
    assert any(s.name == "Watchlist domain match" for s in mine.signals)


def test_a_feed_indicator_for_your_email_matches_too():
    a = pipeline.analyse(ioc("Stealer indicator: ceo@acme.example confidence 80", 80), [], ["ceo@acme.example"], get_classifier())
    assert any(s.name == "Watchlist email match" for s in a.signals) and a.severity in ("high", "critical")


# ---- evaluation tools ----

def write_csv(path, rows, header=("text", "label")):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def test_the_shipped_template_is_a_valid_labelled_file():
    from pathlib import Path
    texts, labels = realeval.load_csv(str(Path(__file__).resolve().parents[1] / "data" / "real_labelled" / "template.csv"))
    assert len(texts) == len(labels) == 3 and set(labels) <= set(realeval.CATEGORIES)


def test_load_csv_reads_labelled_rows_and_skips_empty_text(tmp_path):
    p = tmp_path / "l.csv"
    write_csv(p, [("Selling 0day RCE", "exploit_sale"), ("", "benign"), ("Lunch menu today", "benign")])
    assert realeval.load_csv(str(p)) == (["Selling 0day RCE", "Lunch menu today"], ["exploit_sale", "benign"])


@pytest.mark.parametrize("rows,header,message", [
    ([("x", "not_a_class")], ("text", "label"), "not one of"),
    ([("x", "benign")], ("body", "label"), "missing column"),
    ([], ("text", "label"), "no labelled rows"),
])
def test_load_csv_explains_what_is_wrong(tmp_path, rows, header, message):
    p = tmp_path / "bad.csv"
    write_csv(p, rows, header)
    with pytest.raises(ValueError, match=message):
        realeval.load_csv(str(p))


def test_score_labelled_reports_f1_per_predictor_and_warns_when_small():
    texts = ["Selling 0day RCE for Exchange, price 2 XMR", "Company picnic photos from Friday", "decrypt your files, pay the ransom"]
    labels = ["exploit_sale", "benign", "ransomware_leak"]
    r = realeval.score_labelled(get_classifier(), texts, labels)
    assert r["n"] == 3 and set(r["macro_f1"]) == {"rules", "ml", "hybrid"} and 0 <= r["accuracy"] <= 1
    assert "rough guide" in r["warning"]


def test_score_feedback_handles_none_and_some():
    clf = get_classifier()
    assert realeval.score_feedback(clf, [])["n"] == 0
    rows = [{"title": "0day", "text": "Selling 0day RCE for Exchange, 2 XMR", "category": "exploit_sale", "verdict": "correct"},
            {"title": "x", "text": "ransom will be published", "category": "ransomware_leak", "verdict": "wrong"}]
    r = realeval.score_feedback(clf, rows)
    assert r["n"] == 2 and r["agreement"] == 0.5 and "macro_f1" in r


def test_live_claims_check_counts_recall_and_lists_misses():
    items = [claim(), Item(source="x", kind="post", title="odd", text="Hello, how are you today?")]
    r = realeval.live_claims_check(get_classifier(), items, pipeline.analyse)
    assert r["n"] == 2 and r["recognised_as_ransomware_leak"] == 1 and r["recall"] == 0.5
    assert r["lowest_scoring_missed"][0]["title"] == "odd"
    assert realeval.live_claims_check(get_classifier(), [], pipeline.analyse)["recall"] is None
