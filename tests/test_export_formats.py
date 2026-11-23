"""MISP export and the read-only TAXII 2.1 endpoints."""
import json

import pytest
from fastapi.testclient import TestClient

from darklens import export
from helpers import load_app


@pytest.fixture
def client(monkeypatch):
    with TestClient(load_app(monkeypatch).app) as c:
        yield c


def _alert(i="a1", **kw):
    base = {"item_id": i, "title": "Acme database for sale", "category": "credential_dump", "severity": "high", "score": 80,
            "seen_at": "2026-11-20", "iocs": {"domain": ["evil.example"], "ipv4": ["203.0.113.5"], "cve": ["CVE-2026-1"],
                                               "eth": ["0xabc"], "btc": ["bc1qxyz"]}, "signals": [], "demo": False}
    base.update(kw)
    return base


def test_misp_event_shape_and_skips_unsupported_types():
    ev = export.to_misp([_alert()])["response"][0]["Event"]
    types = {(a["type"], a["value"]) for a in ev["Attribute"]}
    assert ("domain", "evil.example") in types and ("ip-dst", "203.0.113.5") in types and ("btc", "bc1qxyz") in types
    assert all(t != "eth" for t, _ in types)
    assert ev["date"] == "2026-11-20" and ev["threat_level_id"] == "1" and ev["published"] is False
    cve = next(a for a in ev["Attribute"] if a["type"] == "vulnerability")
    assert cve["to_ids"] is False
    json.dumps(export.to_misp([_alert()]))


def test_misp_is_deterministic_and_survives_odd_input():
    assert export.to_misp([_alert()]) == export.to_misp([_alert()])
    out = export.to_misp([_alert(seen_at="not a date", iocs={}, title=None, severity="weird"), _alert("a2", iocs={"domain": ["x.io", "x.io"]})])
    assert out["response"][0]["Event"]["Attribute"] == []
    assert len(out["response"][1]["Event"]["Attribute"]) == 1
    assert export.to_misp([]) == {"response": []}


def test_taxii_paging_and_type_filter():
    alerts = [_alert(f"a{i}") for i in range(4)]
    first = export.taxii_objects(alerts, limit=3)
    assert first["more"] is True and first["next"] == "3" and len(first["objects"]) == 3
    rest = export.taxii_objects(alerts, limit=100, offset=3)
    total = len(export.to_stix(alerts)["objects"])
    assert len(first["objects"]) + len(rest["objects"]) == total
    only = export.taxii_objects(alerts, types={"report"})
    assert {o["type"] for o in only["objects"]} == {"report"} and len(only["objects"]) == 4


def test_taxii_endpoints(client):
    r = client.get("/taxii2/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/taxii+json")
    assert r.json()["api_roots"][0].endswith("/taxii2/root/")
    assert client.get("/taxii2/root/").json()["versions"] == [export.TAXII_TYPE]
    cid = client.get("/taxii2/root/collections/").json()["collections"][0]["id"]
    assert client.get(f"/taxii2/root/collections/{cid}/").json()["can_write"] is False
    env = client.get(f"/taxii2/root/collections/{cid}/objects/?limit=5").json()
    assert len(env["objects"]) <= 5 and "more" in env
    assert client.get("/taxii2/root/collections/nope/objects/").status_code == 404
    assert client.get(f"/taxii2/root/collections/{cid}/objects/?next=abc").status_code == 400
    assert client.get(f"/taxii2/root/collections/{cid}/objects/?limit=0").status_code == 422
    assert client.get(f"/taxii2/root/collections/{cid}/objects/?next=99999999999999").json()["objects"] == []


def test_misp_endpoint(client):
    r = client.get("/api/export/misp.json")
    assert r.status_code == 200 and "response" in r.json()
