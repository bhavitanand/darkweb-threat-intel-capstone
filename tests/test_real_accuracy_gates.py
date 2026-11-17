"""Accuracy gates on REAL text that runs in CI: the committed breach write-ups (CC BY 4.0) and advisories (public domain).

A model is trained only on data before a cutoff and measured on what it never saw, so a change that makes real-world
accuracy worse fails the build. (The news-based checks use third-party text that cannot be committed; they are in
tests_real/ and run locally.)
"""
import pytest

from darklens.nlp import realeval


@pytest.fixture(scope="module")
def report():
    return realeval.holdout_report("2026-01-01")


def test_enough_unseen_real_examples_are_tested(report):
    assert report["breaches_tested"] >= 100 and report["advisories_tested"] >= 150


def test_unseen_real_breaches_are_detected_and_typed(report):
    assert report["breach_alert_rate"] >= 0.95, report
    assert report["breach_right_type_rate"] >= 0.90, report
    assert report["breach_medium_or_higher_rate"] >= 0.80, report


def test_unseen_real_advisories_do_not_raise_alerts(report):
    """Security vocabulary is not a threat: a patch notice must not become an alert."""
    assert report["advisory_false_alarm_rate"] <= 0.02, report
    assert report["advisory_false_alarm_medium_or_higher_rate"] == 0.0, report
