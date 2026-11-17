"""Training on real text (breach write-ups and advisories), the model cache, and the rules written from real wording."""
import time

import numpy as np
import pytest

from darklens import pipeline
from darklens.models import Item
from darklens.nlp import classifier as C
from darklens.nlp import realdata
from darklens.rules.engine import run_rules


def fired(text):
    return {r.id for r, _ in run_rules(text)}


# ---------------- the committed real datasets ----------------

def test_the_committed_datasets_exist_and_are_well_formed():
    hibp, nvd = realdata.load(realdata.HIBP_CSV), realdata.load(realdata.NVD_CSV)
    assert len(hibp) > 800 and len(nvd) > 800
    for rows, label in ((hibp, "credential_dump"), (nvd, "benign")):
        assert {r["label"] for r in rows} == {label}
        assert all(r["text"] and r["added"] and r["id"] for r in rows)
        assert len({r["id"] for r in rows}) == len(rows)  # no duplicates
        assert all(len(r["text"]) <= 1500 for r in rows)


def test_no_html_or_markup_survived_cleaning():
    for r in realdata.load(realdata.HIBP_CSV):
        assert "<a " not in r["text"] and "&amp;" not in r["text"] and "  " not in r["text"]


def test_training_rows_respects_a_date_cutoff():
    everything = realdata.training_rows()
    early = realdata.training_rows(before="2025-01-01")
    assert 0 < len(early) < len(everything)
    assert all(r["added"] < "2025-01-01" for r in early)
    assert realdata.training_rows(before="1900-01-01") == []


def test_the_advisory_holdout_is_stable_and_about_a_fifth():
    nvd = realdata.load(realdata.NVD_CSV)
    held = [r for r in nvd if C.nvd_holdout(r)]
    assert held == [r for r in nvd if C.nvd_holdout(r)]  # deterministic
    assert 0.1 < len(held) / len(nvd) < 0.3


def test_fetching_parses_the_public_formats_and_skips_junk():
    breaches = [
        {"Name": "Good", "AddedDate": "2026-01-02T03:04:05Z", "Description": 'In 2026, <a href="x">Good</a> &amp; Co suffered a data breach exposing emails.'},
        {"Name": "Spam", "AddedDate": "2026-01-02T00:00:00Z", "Description": "x" * 100, "IsSpamList": True},
        {"Name": "Fake", "AddedDate": "2026-01-02T00:00:00Z", "Description": "x" * 100, "IsFabricated": True},
        {"Name": "Short", "AddedDate": "2026-01-02T00:00:00Z", "Description": "tiny"},
    ]
    got = realdata.fetch_hibp(get=lambda url: breaches)
    assert [r["id"] for r in got] == ["hibp-Good"] and got[0]["text"] == "In 2026, Good & Co suffered a data breach exposing emails." and got[0]["added"] == "2026-01-02"
    cves = {"vulnerabilities": [{"cve": {"id": "CVE-2026-1", "published": "2026-02-03T00:00:00",
                                         "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "A flaw in Example allows remote attackers to run code. " * 2}]}},
                                {"cve": {"id": "CVE-2026-2", "descriptions": [{"lang": "en", "value": "** REJECT ** this was withdrawn and is not a vulnerability at all"}]}},
                                {"cve": {"id": "CVE-2026-3", "descriptions": []}}]}
    out = realdata.fetch_nvd(windows=1, per_window=10, get=lambda url: cves, pause=0)
    assert [r["id"] for r in out] == ["CVE-2026-1"] and out[0]["label"] == "benign"


def test_one_failing_window_does_not_lose_the_rest():
    calls = []

    def get(url):
        calls.append(url)
        if len(calls) == 1:
            raise ConnectionError("down")
        return {"vulnerabilities": [{"cve": {"id": f"CVE-2026-{len(calls)}", "published": "2026-01-01T00:00:00",
                                             "descriptions": [{"lang": "en", "value": "A flaw lets remote attackers run arbitrary code on the host. " * 2}]}}]}
    assert len(realdata.fetch_nvd(windows=3, per_window=5, get=get, pause=0)) == 2


# ---------------- training ----------------

def test_the_cutoff_keeps_later_breaches_out_of_training(monkeypatch):
    seen = {}
    real_fit = C.ThreatClassifier.fit

    def spy(self, texts, labels, sample_weight=None):
        seen["n"], seen["w"] = len(texts), sample_weight
        return real_fit(self, texts, labels, sample_weight)
    monkeypatch.setattr(C.ThreatClassifier, "fit", spy)
    C.train_default(save=False, real=False)
    n_synth = seen["n"]
    assert seen["w"] is None
    C.train_default(save=False, real=True, hibp_before="2026-01-01", hold_out_nvd=True)
    with_cutoff = seen["n"]
    C.train_default(save=False, real=True)
    assert n_synth < with_cutoff < seen["n"]
    w = seen["w"]
    assert len(w) == seen["n"] and set(np.unique(w)) == {1.0, C.REAL_WEIGHT, C.REAL_NVD_WEIGHT}


def test_synthetic_only_training_still_works():
    clf = C.train_default(save=False, real=False)
    assert set(clf.classes_) >= {"benign", "credential_dump", "ransomware_leak"}


# ---------------- the model cache ----------------

def test_the_model_is_loaded_once_not_per_call(monkeypatch):
    C.get_classifier()  # make sure a saved file exists and is cached
    loads = []
    real_load = C.ThreatClassifier.load
    monkeypatch.setattr(C.ThreatClassifier, "load", staticmethod(lambda *a, **k: (loads.append(1), real_load(*a, **k))[1]))
    t = time.perf_counter()
    for _ in range(50):
        C.get_classifier()
    assert loads == [] and time.perf_counter() - t < 0.5


def test_a_newer_model_file_is_picked_up(monkeypatch, tmp_path):
    path = tmp_path / "m.joblib"
    monkeypatch.setattr(C, "MODEL_PATH", path)
    C._CACHE.clear()
    first = C.get_classifier()           # nothing on disk: trains and saves
    assert path.exists() and C.get_classifier() is first
    import os
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 5_000_000_000))
    assert C.get_classifier() is not first  # the file changed, so it is reloaded
    C._CACHE.clear()


def test_a_damaged_model_file_is_replaced_not_fatal(monkeypatch, tmp_path):
    path = tmp_path / "bad.joblib"
    path.write_bytes(b"not a model")
    monkeypatch.setattr(C, "MODEL_PATH", path)
    C._CACHE.clear()
    assert C.get_classifier().classes_
    C._CACHE.clear()


# ---------------- strong rules beat a text model that thinks "benign" ----------------

def test_a_strong_rule_all_but_removes_benign():
    clf = C.get_classifier()
    p = clf.classify("Looking to sell a working exploit for Confluence, remote code execution, no user interaction.")
    assert p[0] == "exploit_sale" and p[1] > 0.5


def test_suppression_scales_with_how_strong_the_rule_is(monkeypatch):
    clf = C.get_classifier()
    strong = "Looking to sell a working exploit for Confluence, remote code execution"
    weak = "Please vouch for the new conference schedule, thanks"  # only the weak escrow-and-trust rule fires
    benign = clf.classes_.index("benign")
    monkeypatch.setattr(C.ThreatClassifier, "BENIGN_SUPPRESSION", 0.0)
    off_strong, off_weak = (clf.predict_proba([t])[0][benign] for t in (strong, weak))
    monkeypatch.setattr(C.ThreatClassifier, "BENIGN_SUPPRESSION", 0.95)
    on_strong, on_weak = (clf.predict_proba([t])[0][benign] for t in (strong, weak))
    assert on_strong < off_strong          # a strong rule pushes benign down harder when suppression is on
    assert abs(on_weak - off_weak) < 1e-9  # a weak rule is already at the old floor, so it is unchanged


# ---------------- rules written from real wording ----------------

BREACH_REPORTS = [
    "In May 2017, the education platform Edmodo was hacked resulting in the exposure of 77 million records.",
    "In January 2023, 1.4M records from a vehicle marketplace appeared on a popular hacking forum.",
    "In April 2018, a credential stuffing list containing 111 million email addresses and passwords was discovered.",
    "In 2024, data relating to an unknown service appeared in a publicly exposed database.",
    "The company was breached and ransomed; the data containing 5.4M email addresses was subsequently dumped publicly.",
    "In August 2018, the spyware company left terabytes of data publicly exposed on an open server.",
]
EVERYDAY = [
    "The server was hacked together over a weekend as a hackathon project and the demo went well.",
    "My account password was reset after I forgot it, and my emails are all back.",
    "Mozilla published a security update; users should install the latest release.",
    "The accounts team posted the quarterly records to the shared drive.",
    "A new database engine was released with faster queries and better indexes.",
    "Researchers hacked their own car to show how steering works, in a controlled lab.",
    "How to protect your email and passwords with a password manager and two factor authentication.",
]


@pytest.mark.parametrize("text", BREACH_REPORTS)
def test_real_breach_wording_is_recognised(text):
    assert fired(text) & {"DL-CRD-006", "DL-CRD-007", "DL-CRD-008"}


@pytest.mark.parametrize("text", EVERYDAY)
def test_everyday_text_does_not_trigger_the_breach_rules(text):
    assert not fired(text) & {"DL-CRD-006", "DL-CRD-007", "DL-CRD-008"}, text


@pytest.mark.parametrize("text,rule", [
    ("Looking to sell a working exploit for Confluence", "DL-EXP-001"),
    ("Access broker listing: VPN foothold at a hospital, 2 XMR, escrow via admin", "DL-EXP-003"),
    ("Operation announced: our group is going to breach telecom providers this quarter", "DL-GEN-001"),
    ("Hacktivist call to arms, targets are retail and energy", "DL-GEN-001"),
])
def test_sale_and_planning_wording_is_recognised(text, rule):
    assert rule in fired(text)


@pytest.mark.parametrize("text", [
    "Security researchers sell tickets to the exploit development workshop next month",
    "The vendor will sell the product through resellers and offer an extended warranty",
    "Our group is going to the conference this quarter to hear about breach response",
    "We plan to target a 10% increase in sales and hit our retail goals this year",
    "Fortinet fixes a flaw that allowed a foothold in some networks, no price increase planned",
])
def test_ordinary_sentences_do_not_trigger_sale_or_planning_rules(text):
    assert not fired(text) & {"DL-EXP-001", "DL-EXP-003", "DL-GEN-001"}, text


def test_ordinary_news_is_still_not_an_alert():
    clf = C.get_classifier()
    for text in ["UK economy grows at fastest rate for more than two years",
                 "Microsoft fixes almost 1,100 security vulnerabilities in this month's Patch Tuesday",
                 "How to spot a Black Friday scam and stay safe online"]:
        a = pipeline.analyse(Item(source="m", kind="post", title="", text=text), [], [], clf)
        assert a.score == 0, text
