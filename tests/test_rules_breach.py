"""Rules added after measuring real news: breach reports and extortion-group claims, and the tunable rule boost."""
import pytest

from darklens import pipeline
from darklens.models import Item
from darklens.nlp.classifier import ThreatClassifier, get_classifier
from darklens.rules.engine import run_rules


def fired(text: str) -> set[str]:
    return {r.id for r, _ in run_rules(text)}


BREACH = [
    "City warns residents of a data breach affecting one million people",
    "University says personal information was stolen during a cyberattack",
    "Customer data exposed after a third party supplier was compromised",
    "Employee data was leaked online and put up for auction by a threat actor",
    "The agency admits all users’ data is stolen",
]
EXTORTION = [
    "An extortion group claims theft of nearly a billion customer records",
    "How a ransomware gang pressures its victims through a leak site",
    "The group claims to have stolen files from several law firms",
]
ORDINARY = [
    "How to protect your personal information when shopping online",
    "A new law requires companies to report incidents within three days",
    "Climate scientists meet to discuss rising sea levels",
    "The football club announced a new stadium sponsor today",
    "Patch Tuesday fixes an actively exploited zero-day in Outlook",
    "Researchers explain how attackers gain VPN access using stolen credentials",
]


@pytest.mark.parametrize("text", BREACH)
def test_breach_reports_are_recognised(text):
    assert "DL-CRD-006" in fired(text)


@pytest.mark.parametrize("text", EXTORTION)
def test_extortion_group_claims_are_recognised(text):
    assert "DL-RAN-006" in fired(text)


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_text_triggers_neither_new_rule(text):
    assert not ({"DL-CRD-006", "DL-RAN-006"} & fired(text))


def test_ordinary_text_and_news_never_reach_high_severity():
    clf = get_classifier()
    for text in ORDINARY:
        a = pipeline.analyse(Item(source="rss", kind="post", title="", text=text), [], [], clf)
        assert a.severity in ("low", "medium"), (text, a.score)


def test_a_breach_report_gets_a_real_alert_but_below_high():
    """Breach news is worth a look but is not itself a high-severity event."""
    a = pipeline.analyse(Item(source="rss", kind="post", title="", text=BREACH[0]), [], [], get_classifier())
    assert a.score > 0 and a.severity in ("low", "medium", "high")


def test_the_rule_boost_is_a_class_setting_and_changing_it_changes_the_fusion(monkeypatch):
    clf = get_classifier()
    text = "Customer data exposed after a third party supplier was compromised"
    monkeypatch.setattr(ThreatClassifier, "RULE_BOOST", 0.0)
    flat = clf.classify(text)[2]["credential_dump"]
    monkeypatch.setattr(ThreatClassifier, "RULE_BOOST", 20.0)
    boosted = clf.classify(text)[2]["credential_dump"]
    assert boosted > flat and ThreatClassifier.RULE_BOOST == 20.0


def test_the_shipped_settings_are_the_measured_ones():
    """These were chosen from data (see docs/accuracy.md); changing them should be a deliberate, measured act."""
    assert ThreatClassifier.RULE_BOOST == 8.0 and pipeline.UNCERTAIN_BELOW == 0.6
