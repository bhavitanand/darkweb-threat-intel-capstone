"""Every component, exercised on REAL text instead of synthetic samples.

Run:  python -m pytest tests_real -q

The real text comes from the git-ignored labelling folder (public news items collected by `label pool`, plus the
labelled sets), so these tests are skipped on a machine without it and are not part of CI. They are the "does it behave
on the real world" gate: robustness on every collected item, determinism, speed, the whole API on real alerts, the
exports, and accuracy floors on the labelled sets so a change cannot quietly make real-data results worse.
"""
import csv
import json
import statistics
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

POOL = ROOT / "labelling" / "candidates.csv"
TUNING = ROOT / "labelling" / "silver" / "agreed.csv"
UNTOUCHED = ROOT / "labelling" / "test" / "silver" / "agreed.csv"

pytestmark = pytest.mark.skipif(not POOL.exists(), reason="no real data here (labelling/ is private and git-ignored)")


def _read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="module")
def pool():
    return _read(POOL)


@pytest.fixture(scope="module")
def clf():
    from darklens.nlp.classifier import get_classifier
    return get_classifier()


def _item(row):
    from darklens.models import Item
    return Item(source="rss", kind="post", title="", text=row["text"])


# ---------------- robustness and determinism on every real item ----------------

def test_every_real_item_is_analysed_without_error_and_scores_are_sane(pool, clf):
    from darklens import pipeline
    bad = []
    for r in pool:
        a = pipeline.analyse(_item(r), [], [], clf)
        if not (0 <= a.score <= 100) or a.severity not in ("low", "medium", "high", "critical"):
            bad.append((r["id"], a.score, a.severity))
        if a.score > 0 and not a.signals:
            bad.append((r["id"], "alert without a reason"))
    assert not bad, bad[:5]


def test_analysis_is_deterministic_on_real_text(pool, clf):
    from darklens import pipeline
    sample = pool[::7][:60]
    first = [(pipeline.analyse(_item(r), [], [], clf).score, pipeline.analyse(_item(r), [], [], clf).category) for r in sample]
    second = [(pipeline.analyse(_item(r), [], [], clf).score, pipeline.analyse(_item(r), [], [], clf).category) for r in sample]
    assert first == second


def test_speed_on_real_text(pool, clf):
    """A visitor pasting a post should not wait: median under 50 ms, slowest under 1 s, on this machine."""
    from darklens import pipeline
    times = []
    for r in pool[:150]:
        t = time.perf_counter()
        pipeline.analyse(_item(r), [], [], clf)
        times.append(time.perf_counter() - t)
    assert statistics.median(times) < 0.05 and max(times) < 1.0, (statistics.median(times), max(times))


def test_indicator_extraction_on_real_text_is_well_formed(pool):
    import re
    from darklens.extract.iocs import extract_iocs
    host = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
    found = 0
    for r in pool:
        for kind, values in extract_iocs(r["text"]).items():
            for v in values:
                found += 1
                assert v and v == v.strip() and "\n" not in v, (kind, v)
                if kind == "domain":
                    assert host.match(v.lower()), v
    assert found > 0


def test_masking_never_changes_ordinary_real_text(pool):
    from darklens.breach.hibp import mask_combolist
    changed = [r["text"][:80] for r in pool if mask_combolist(r["text"]) != r["text"]]
    assert not changed, changed[:3]


# ---------------- watchlist behaviour on real text ----------------

def test_watching_common_software_does_not_alert_on_ordinary_real_news(pool, clf):
    """The watchlist must not turn everyday news into alerts. Ordinary items = ones that scored 0 with no watchlist."""
    from darklens import pipeline
    quiet = [r for r in pool if pipeline.analyse(_item(r), [], [], clf).score == 0][:150]
    assert len(quiet) > 50
    noisy = []
    for r in quiet:
        a = pipeline.analyse(_item(r), [], [], clf, ["microsoft", "google", "apple"])
        if a.score >= 70:
            noisy.append((a.score, r["text"]))
    # A High alert from a watched vendor needs an attack or breach in the same text, not just a patch or a mention.
    for score, text in noisy:
        assert any(w in text.lower() for w in ("exploit", "zero-day", "0-day", "in the wild", "breach", "attack", "compromis", "ransomware", "backdoor", "hijack", "malware", "exfiltrat", "stolen", "leaked")), (score, text[:100])


# ---------------- the whole API on real alerts ----------------

@pytest.fixture(scope="module")
def api(pool):
    import os
    import tempfile

    from fastapi.testclient import TestClient
    from helpers import load_app

    from darklens import pipeline
    from darklens.models import Item

    class MP:  # a tiny stand-in for pytest's monkeypatch at module scope
        def setenv(self, k, v):
            os.environ[k] = v

        def delenv(self, k, raising=True):
            os.environ.pop(k, None)

        def setattr(self, *a, **k):
            pass

    tmp = tempfile.mkdtemp()
    os.environ["DARKLENS_DB"] = str(Path(tmp) / "real.db")
    module = load_app(MP())
    with TestClient(module.app) as c:
        c.module = module
        # leak-claim-shaped items too, so the restricted-source path is exercised on real-looking data
        items = [Item(source="rss", kind="post", title=r["text"].split(". ")[0][:120], text=r["text"]) for r in pool]
        items.append(Item(source="ransomware.live", kind="leak_claim", title="Real Corp", actor="grp",
                          text="Claimed secretword text", meta={"no_redistribute": True}))
        pipeline.run(items=items, con=module.con())
        yield c


def test_api_endpoints_work_on_real_alerts(api):
    stats = api.get("/api/stats").json()
    assert stats["alerts"] > 0 and stats["items"] >= stats["alerts"]
    total = int(api.get("/api/alerts?limit=1").headers["x-total-count"])
    assert total == stats["alerts"]
    assert api.get("/api/graph").status_code == 200
    assert api.get("/api/ingest/status").status_code == 200


def test_paging_covers_every_real_alert_exactly_once(api):
    total = int(api.get("/api/alerts?limit=1").headers["x-total-count"])
    seen, offset = [], 0
    while offset < total:
        page = api.get(f"/api/alerts?limit=250&offset={offset}").json()
        assert page, offset
        seen += [a["item_id"] for a in page]
        offset += 250
    assert len(seen) == total == len(set(seen))


def test_every_filter_combination_is_consistent_with_the_total(api):
    for sev in ("low", "medium", "high", "critical"):
        r = api.get(f"/api/alerts?severity={sev}&limit=5000")
        assert int(r.headers["x-total-count"]) == len(r.json()) and all(a["severity"] == sev for a in r.json())


def test_alert_detail_and_evidence_pack_for_real_alerts(api):
    rows = api.get("/api/alerts?limit=40").json()
    for a in rows[:25]:
        d = api.get(f"/api/alerts/{a['item_id']}")
        assert d.status_code == 200 and d.json()["signals"]
        ev = api.get(f"/api/alerts/{a['item_id']}/evidence")
        assert ev.status_code == 200 and "<script" not in ev.text.lower()


def test_exports_on_real_alerts_are_safe(api):
    csv_text = api.get("/api/export/alerts.csv").text
    for line in csv_text.splitlines()[1:]:
        for cell in next(csv.reader([line]), []):
            assert not cell.startswith(("=", "+", "@", "\t")), cell[:40]  # spreadsheet formula injection
    stix = api.get("/api/export/stix.json").json()
    assert stix["type"] == "bundle" and all("id" in o and "type" in o for o in stix["objects"])
    assert "secretword" not in csv_text and "secretword" not in json.dumps(stix)


def test_restricted_source_text_is_never_returned_or_searchable(api):
    assert api.get("/api/alerts", params={"q": "secretword"}).json() == []
    row = next(a for a in api.get("/api/alerts", params={"q": "real corp"}).json() if a["title"] == "Real Corp")
    assert row["text"] == "" and row["restricted"] is True
    assert "secretword" not in json.dumps(api.get(f"/api/alerts/{row['item_id']}").json())


# ---------------- accuracy floors on the labelled real sets ----------------

def _score(path, clf):
    from darklens import pipeline
    from darklens.nlp import realeval
    texts, labels = realeval.load_csv(str(path))
    return realeval.score_pipeline(clf, texts, labels, analyse=pipeline.analyse), labels


@pytest.mark.skipif(not TUNING.exists(), reason="tuning set not present")
def test_tuning_set_floors(clf):
    r, labels = _score(TUNING, clf)
    assert r["false_alarm_medium_or_higher_rate"] <= 0.01, r["false_alarm_medium_or_higher_rate"]
    assert r["false_alarm_rate"] <= 0.03, r["false_alarm_rate"]
    assert r["threats_missed_rate"] <= 0.2, r["threats_missed_rate"]


@pytest.mark.skipif(not UNTOUCHED.exists(), reason="17 November set not present")
def test_17_november_set_floors(clf):
    """The set is spent (rules were fixed after seeing it), so this is a regression gate, not an honest test."""
    r, labels = _score(UNTOUCHED, clf)
    assert r["false_alarm_rate"] == 0.0 and r["false_alarm_medium_or_higher_rate"] == 0.0
    assert r["threats_missed_rate"] <= 0.12, r["threats_missed_rate"]
