"""CSV and STIX 2.1 export: safe for spreadsheets, and valid against the real STIX library when it is installed."""
import csv
import io
from datetime import datetime, timezone

import pytest

from darklens import export

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


def alert(**kw):
    base = dict(item_id="abc123", severity="high", score=80, category="credential_dump", confidence=0.91,
                title="Dump of acme.example", source="forum", actor="x", org="Acme", country="IN",
                seen_at="2026-11-15", created_at="2026-11-16T10:00:00Z", url="https://example.org/p", demo=False,
                signals=[{"name": "Combolist format", "score": 80, "why": "w", "evidence": "e", "full": False},
                         {"name": "Classifier", "score": 40, "why": "w", "evidence": "e", "full": False}],
                iocs={"ipv4": ["8.8.8.8"], "domain": ["evil.example"], "sha256": ["a" * 64], "md5": ["b" * 32],
                      "email": ["x@evil.example"], "url": ["http://evil.example/a?b='c'"], "cve": ["CVE-2026-5555"],
                      "btc": ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"], "onion": ["abcdefghij234567.onion"]})
    base.update(kw)
    return base


# ---- CSV ----

@pytest.mark.parametrize("evil", ["=HYPERLINK(\"http://x\",\"c\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd"])
def test_csv_neutralises_spreadsheet_formulas(evil):
    row = next(csv.DictReader(io.StringIO(export.to_csv([alert(title=evil, actor=evil)]))))
    assert row["title"].startswith("'") and row["actor"].startswith("'")


def test_csv_roundtrip_with_commas_quotes_and_newlines():
    title = 'He said "hi", then\nleft'
    rows = list(csv.DictReader(io.StringIO(export.to_csv([alert(title=title)]))))
    assert rows[0]["title"] == title and rows[0]["top_reasons"].startswith("Combolist format")
    assert "ipv4:8.8.8.8" in rows[0]["indicators"] and rows[0]["demo"] == "no"


def test_csv_handles_missing_fields_and_empty_input():
    assert export.to_csv([]).strip().split(",")[0] == "id"
    sparse = alert(title=None, actor=None, org=None, url=None, signals=[], iocs={}, seen_at=None)
    assert list(csv.DictReader(io.StringIO(export.to_csv([sparse]))))[0]["title"] == ""


# ---- STIX ----

def test_stix_bundle_shape_and_determinism():
    b1 = export.to_stix([alert()], now=NOW)
    b2 = export.to_stix([alert()], now=NOW)
    assert b1 == b2
    types = [o["type"] for o in b1["objects"]]
    assert types[0] == "identity" and types.count("report") == 1 and "vulnerability" in types
    report = next(o for o in b1["objects"] if o["type"] == "report")
    assert report["x_darklens_wallets"] == ["btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]
    assert report["confidence"] == 80 and set(report["object_refs"]) <= {o["id"] for o in b1["objects"]}


def test_stix_indicators_are_deduplicated_across_alerts():
    b = export.to_stix([alert(item_id="a"), alert(item_id="b")], now=NOW)
    assert sum(1 for o in b["objects"] if o["type"] == "indicator" and "8.8.8.8" in o["pattern"]) == 1
    assert sum(1 for o in b["objects"] if o["type"] == "report") == 2


def test_stix_escapes_quotes_in_patterns():
    b = export.to_stix([alert()], now=NOW)
    pat = next(o["pattern"] for o in b["objects"] if o["type"] == "indicator" and "url:value" in o["pattern"])
    assert pat == "[url:value = 'http://evil.example/a?b=\\'c\\'']"


def test_stix_report_without_indicators_still_has_object_refs():
    r = next(o for o in export.to_stix([alert(iocs={})], now=NOW)["objects"] if o["type"] == "report")
    assert r["object_refs"]  # STIX requires at least one


def test_stix_demo_alerts_are_labelled():
    r = next(o for o in export.to_stix([alert(demo=True)], now=NOW)["objects"] if o["type"] == "report")
    assert "demo-data" in r["labels"]


@pytest.mark.parametrize("seen", [None, "", "garbage", "2026-11-15", "2026-11-15T10:00:00Z"])
def test_stix_timestamps_always_parse(seen):
    b = export.to_stix([alert(seen_at=seen, created_at=seen)], now=NOW)
    stix2 = pytest.importorskip("stix2")
    stix2.parse(b, allow_custom=True)


def test_stix_bundle_is_valid_per_the_real_library():
    stix2 = pytest.importorskip("stix2")
    bundle = stix2.parse(export.to_stix([alert(), alert(item_id="z", iocs={}, score=5, severity="low")], now=NOW),
                         allow_custom=True)
    assert len(bundle.objects) >= 5
