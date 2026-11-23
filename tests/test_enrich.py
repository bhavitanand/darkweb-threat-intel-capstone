import time

import pytest

from darklens import enrich


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    enrich._cache.clear(); enrich._calls.clear()
    for k in ("OTX_API_KEY", "VIRUSTOTAL_API_KEY", "GREYNOISE_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def test_validation_blocks_url_tricks():
    assert enrich.normalise("ipv4", " 203.0.113.5 ") == "203.0.113.5"
    for bad in ("999.1.1.1", "1.1.1.1/../x", "a.com/../../x", "a.com?x=1", "http://a.com", "a b.com", "-a.com", ""):
        assert enrich.normalise("ipv4", bad) is None and enrich.normalise("domain", bad) is None
    assert enrich.normalise("domain", "Evil.Example.") == "evil.example"
    assert enrich.normalise("sha256", "A" * 64) == "a" * 64 and enrich.normalise("sha256", "g" * 64) is None
    with pytest.raises(ValueError):
        enrich.lookup("domain", "../etc")


def test_no_keys_means_empty_answer():
    out = enrich.lookup("domain", "evil.example")
    assert out["providers"] == [] and out["results"] == {}


def test_providers_summaries_and_isolation(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k1"); monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k2"); monkeypatch.setenv("GREYNOISE_API_KEY", "k3")
    seen = []

    def fake(url, headers):
        seen.append(url)
        if "otx" in url:
            return {"pulse_info": {"count": 3}}
        if "virustotal" in url:
            raise RuntimeError("down")
        return {"noise": True, "classification": "malicious"}

    monkeypatch.setattr(enrich, "_get", fake)
    out = enrich.lookup("ipv4", "203.0.113.5")["results"]
    assert out["otx"]["flagged"] and "3 threat reports" in out["otx"]["summary"]
    assert out["virustotal"] == {"error": "That service did not answer."}
    assert out["greynoise"]["flagged"]
    n = len(seen)
    enrich.lookup("ipv4", "203.0.113.5")  # cached: successful answers are not re-fetched
    assert len(seen) == n + 1  # only the failed one is retried


def test_hash_skips_greynoise_and_rate_cap(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "k")
    monkeypatch.setattr(enrich, "_get", lambda u, h: pytest.fail("greynoise handles only IPs"))
    assert enrich.lookup("sha256", "a" * 64)["results"] == {}
    monkeypatch.setenv("OTX_API_KEY", "k")
    monkeypatch.setattr(enrich, "_get", lambda u, h: {"pulse_info": {"count": 0}})
    for i in range(enrich.LIMITS["otx"][0]):
        enrich.lookup("domain", f"d{i}.example")
    assert "busy" in enrich.lookup("domain", "late.example")["results"]["otx"]["error"]


def test_virustotal_budget_is_per_minute_and_per_day(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    calls = []
    monkeypatch.setattr(enrich, "_get", lambda u, h: calls.append(u) or {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}})
    out = [enrich.lookup("domain", f"v{i}.example")["results"]["virustotal"] for i in range(6)]
    assert len(calls) == 4 and sum("busy" in str(o.get("error", "")) for o in out) == 2
    enrich._calls["virustotal"] = [time.time() - 70] * 400  # a full day's use, none in the last minute
    assert "busy" in enrich.lookup("domain", "late.example")["results"]["virustotal"]["error"]


def test_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from helpers import load_app
    with TestClient(load_app(monkeypatch).app) as c:
        assert c.get("/api/enrich?kind=domain&value=evil.example").json()["providers"] == []
        assert c.get("/api/enrich?kind=url&value=x").status_code == 400
        assert c.get("/api/enrich?kind=domain&value=../x").status_code == 400
        assert c.get("/api/enrich?kind=domain").status_code == 422
