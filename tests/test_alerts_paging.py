"""Server-side filtering and paging of the alerts list."""
import pytest
from fastapi.testclient import TestClient
from helpers import load_app


@pytest.fixture
def client(monkeypatch):
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


def ids(r):
    return [a["item_id"] for a in r.json()]


def test_total_count_header_matches_the_unfiltered_list(client):
    r = client.get("/api/alerts?limit=3")
    total = int(r.headers["x-total-count"])
    assert len(r.json()) == 3 and total == len(client.get("/api/alerts").json()) and total > 3


def test_pages_do_not_overlap_and_cover_everything_in_order(client):
    everything = ids(client.get("/api/alerts?limit=5000"))
    page1 = ids(client.get("/api/alerts?limit=4&offset=0"))
    page2 = ids(client.get("/api/alerts?limit=4&offset=4"))
    assert page1 == everything[:4] and page2 == everything[4:8] and not set(page1) & set(page2)


def test_offset_past_the_end_is_empty_not_an_error(client):
    r = client.get("/api/alerts?limit=10&offset=100000")
    assert r.status_code == 200 and r.json() == [] and int(r.headers["x-total-count"]) > 0


def test_filters_apply_before_the_limit(client):
    """The old behaviour limited first and filtered after, so a filter could hide matches beyond the limit."""
    sev = client.get("/api/alerts").json()[-1]["severity"]
    r = client.get(f"/api/alerts?severity={sev}&limit=1")
    assert len(r.json()) == 1 and r.json()[0]["severity"] == sev
    assert int(r.headers["x-total-count"]) == len([a for a in client.get("/api/alerts").json() if a["severity"] == sev])


def test_category_and_text_filters(client):
    rows = client.get("/api/alerts").json()
    cat = rows[0]["category"]
    r = client.get(f"/api/alerts?category={cat}")
    assert r.json() and all(a["category"] == cat for a in r.json())
    word = rows[0]["title"].split()[0].lower()
    hits = client.get("/api/alerts", params={"q": word}).json()
    assert hits and all(word in (a["title"] + " " + a["text"]).lower() for a in hits)


@pytest.mark.parametrize("q", ["%", "_", "\\", "' OR 1=1 --", "100%"])
def test_text_search_treats_special_characters_literally(client, q):
    r = client.get("/api/alerts", params={"q": q})
    assert r.status_code == 200
    assert all(q.lower() in (a["title"] + " " + a["text"]).lower() for a in r.json())


def test_bad_limit_and_offset_are_clamped(client):
    assert client.get("/api/alerts?limit=0").status_code == 200
    assert len(client.get("/api/alerts?limit=-5").json()) == 1
    assert client.get("/api/alerts?offset=-3&limit=2").status_code == 200


def test_data_filter_splits_real_and_demo(client):
    demo = client.get("/api/alerts?data=demo")
    real = client.get("/api/alerts?data=real")
    assert demo.json() and all(a["demo"] for a in demo.json())
    assert all(not a["demo"] for a in real.json())
    assert int(demo.headers["x-total-count"]) + int(real.headers["x-total-count"]) == int(client.get("/api/alerts").headers["x-total-count"])


def test_search_cannot_reveal_text_a_source_forbids_republishing(client):
    """Ransomware.live text is stored for scoring but never returned. It must not be searchable either."""
    from darklens import pipeline
    from darklens.models import Item
    secret = "zebrafishcanary"
    it = Item(source="ransomware.live", kind="leak_claim", title="Victim Corp", actor="grp",
              text=f"Claimed by group. {secret} internal note", meta={"no_redistribute": True})
    pipeline.run(items=[it], con=client.module.con())
    assert client.get("/api/alerts", params={"q": secret}).json() == []
    assert any(a["title"] == "Victim Corp" for a in client.get("/api/alerts", params={"q": "victim corp"}).json())
