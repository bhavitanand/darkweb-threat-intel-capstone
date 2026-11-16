"""Rules must not fire on ordinary security NEWS, and must keep firing on genuine offers.

These cases come from a measurement on real news (see docs/accuracy.md): three rules matched everyday vocabulary
("zero-day", "initial access", "dumps") with no sale context, so patch-news and incident-response reports scored as
exploit sales or card fraud. The wording below is paraphrased, not copied from any article.
"""
import json
from pathlib import Path

import pytest

from darklens import pipeline
from darklens.models import Item
from darklens.nlp.classifier import get_classifier
from darklens.rules.engine import run_rules


def fired(text: str) -> set[str]:
    return {r.id for r, _ in run_rules(text)}


NEWS = [
    ("Patch Tuesday fixes an actively exploited zero-day in Outlook and several critical flaws", "DL-EXP-001"),
    ("The vendor patched a zero-day that attackers exploited before a fix was available", "DL-EXP-001"),
    ("Microsoft ships fixes for a 0day and hundreds of other security bugs this month", "DL-EXP-001"),
    ("Citrix patches flaws in NetScaler Gateway and the Secure Access Client, including an authentication bypass", "DL-EXP-003"),
    ("Incident response data shows phishing remained the top initial access technique this quarter", "DL-EXP-003"),
    ("Researchers explain how attackers gain VPN access using stolen credentials", "DL-EXP-003"),
    ("Defenders should monitor access to the company network and its employees accounts", "DL-EXP-003"),
    ("Smells from rubbish dumps and industrial sites are being monitored with new sensors", "DL-FRD-001"),
    ("The database dumps were published online after the breach was disclosed", "DL-FRD-001"),
    ("How to keep your CVV safe when shopping online this holiday season", "DL-FRD-001"),
]


@pytest.mark.parametrize("text,rule", NEWS)
def test_ordinary_news_does_not_trigger_the_strong_sale_rules(text, rule):
    assert rule not in fired(text)


@pytest.mark.parametrize("text", [n[0] for n in NEWS if "zero-day" in n[0] or "0day" in n[0]])
def test_patch_news_that_mentions_a_zero_day_is_never_high(text):
    """It used to score as an exploit sale (Medium to High). Now only the weak mention rule fires, so it can reach
    Medium at most (an exploited zero-day is still worth a glance) but never High or Critical."""
    a = pipeline.analyse(Item(source="rss", kind="post", title="", text=text), [], [], get_classifier())
    assert fired(text) == {"DL-EXP-004"} and a.severity in ("low", "medium")


@pytest.mark.parametrize("text", [
    "More initial access listings: Citrix and RDP access, healthcare and logistics. Payment wallet 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 or XMR on request.",
    "Fresh listings of VPN access to hospitals, payment in BTC",
    "Citrix access to a logistics firm, price on request, escrow",
])
def test_sellers_who_never_write_selling_are_still_caught(text):
    """Learned the hard way: a first version required the word 'selling' and missed a genuine access listing."""
    assert "DL-EXP-003" in fired(text)


OFFERS = [
    ("WTS: zero-day RCE in a popular VPN, $15k, escrow accepted", "DL-EXP-001"),
    ("Selling 0day for Exchange, DM for price", "DL-EXP-001"),
    ("Zero-day for sale, working exploit, 2 XMR", "DL-EXP-001"),
    ("Selling RDP access to a US manufacturer, revenue 50M", "DL-EXP-003"),
    ("Initial access for sale: VPN foothold in a telecom, 2 XMR", "DL-EXP-003"),
    ("Selling initial access to a retail company", "DL-EXP-003"),
    ("Citrix access for sale, domain admin, price 3 BTC", "DL-EXP-003"),
    ("Fresh fullz and CVV for sale, high BIN list", "DL-FRD-001"),
    ("Selling card dumps with track1 track2 and pin", "DL-FRD-001"),
    ("cc shop with fresh cvv2, checker included", "DL-FRD-001"),
]


@pytest.mark.parametrize("text,rule", OFFERS)
def test_genuine_offers_still_trigger_the_strong_rules(text, rule):
    assert rule in fired(text)


def test_a_bare_underground_zero_day_post_without_a_price_still_scores():
    a = pipeline.analyse(Item(source="forum", kind="post", title="", text="0day RCE for Fortinet VPN, serious buyers only"),
                         [], [], get_classifier())
    assert "DL-EXP-004" in fired("0day RCE for Fortinet VPN") and a.score > 0


def test_the_demo_posts_that_are_real_offers_keep_their_high_severity():
    posts = json.loads((Path(__file__).resolve().parents[1] / "data" / "samples" / "forum_posts.json").read_text(encoding="utf-8"))
    clf = get_classifier()
    sales = [p for p in posts if "0day" in p["title"].lower() or "access" in p["title"].lower()]
    assert sales
    for p in sales:
        a = pipeline.analyse(Item(source=p["source"], kind="post", title=p["title"], text=p["text"]), [], [], clf)
        assert a.severity in ("high", "critical"), (p["title"], a.score)
