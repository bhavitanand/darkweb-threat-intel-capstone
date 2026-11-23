"""Edge cases: hostile and odd input to every layer. Nothing here may crash, hang, leak or silently misbehave."""
import time

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import pipeline
from darklens.breach.hibp import credential_exposure, mask_combolist
from darklens.extract.iocs import extract_iocs
from darklens.models import Item
from darklens.nlp.classifier import get_classifier

CLF = get_classifier()
N = 20000

# Inputs built to make a regex or a vectoriser slow, plus plain oddities. 20,000 characters is the API's limit.
HOSTILE = {
    "dots": "a." * (N // 2), "emails": "a@b." * (N // 4), "colons": "a@b.com:" * (N // 8), "zeros": "0" * N,
    "ones": "1" * N, "letters": "a" * N, "url": "http://" + "a" * N, "cve": "CVE-2026-" + "1" * N, "btc": "bc1" + "q" * N,
    "onion": "a" * 56 + ".onion" * 500, "dashes": "a-" * (N // 2), "plus": "+" * N, "at": "@" * N, "at_dot": "@." * (N // 2),
    "local@": "u" * 60 + "@" * 1000, "labels": "a" * 60 + "." + "b" * 60 + "." * 500, "xmr": "4" + "A" * N, "trx": "T" * N,
    "eth": "0x" + "a" * N, "defang": "hxxp[:]//" + "[.]" * (N // 3), "newlines": "\n" * N, "spaces_x": " " * N + "x",
    "repeat": "selling exploit " * (N // 16), "combo": "user@example.com:Passw0rd\n" * (N // 28),
    "combo_oneline": "a@b.co:xxxx " * (N // 11), "emoji": "💀" * (N // 2), "rtl": "‮selling‬" * (N // 10),
    "nul": "a\x00b\x00" * (N // 4), "quotes": "'" * N, "backslash": "\\" * N, "percent": "%" * N,
}


@pytest.fixture
def client(monkeypatch):
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


# ---------------- speed: no input may pin the CPU ----------------

@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_is_handled_quickly_by_every_stage(name):
    """Crafted 20,000-character input used to take 6 to 13 seconds (quadratic regexes). The budget is generous for slow
    CI machines but far below that."""
    text = HOSTILE[name]
    stages = {
        "analyse": lambda: pipeline.analyse(Item(source="m", kind="post", title="", text=text), ["example.com"], ["a@example.com"], CLF, ["fortinet"]),
        "iocs": lambda: extract_iocs(text), "mask": lambda: mask_combolist(text),
        "exposure": lambda: credential_exposure(text, ["example.com"]),
    }
    for label, fn in stages.items():
        t = time.perf_counter()
        fn()
        assert time.perf_counter() - t < 1.5, (name, label)


def test_a_title_with_hostile_text_is_also_quick():
    t = time.perf_counter()
    pipeline.analyse(Item(source="m", kind="post", title="a." * 5000, text="b." * 10000), [], [], CLF)
    assert time.perf_counter() - t < 1.5


# ---------------- the bounds must not break real indicators ----------------

def test_bounded_patterns_still_find_realistic_indicators():
    t = ("Contact sales.team@sub.example-corp.co.uk or visit https://login.shop.example.com/a?b=1, host mail.example.org "
         "at 8.8.8.8, CVE-2026-12345, sha256 " + "ab" * 32)
    got = extract_iocs(t)
    assert "sales.team@sub.example-corp.co.uk" in got["email"]
    assert any("login.shop.example.com" in d for d in got.get("domain", []) + got.get("url", []))
    assert "8.8.8.8" in got["ipv4"] and "CVE-2026-12345".upper() in [c.upper() for c in got["cve"]]
    assert len(got["sha256"][0]) == 64


def test_a_long_but_valid_address_and_domain_are_found():
    local = "a" * 64
    host = ".".join(["x" * 63] * 3) + ".com"  # 63-character labels
    assert f"{local}@{host}" in extract_iocs(f"mail {local}@{host} now")["email"]


def test_masking_still_hides_the_whole_password_however_long():
    pw = "P" * 5000 + "!"
    out = mask_combolist(f"ceo@example.com:{pw} and more")
    assert pw not in out and "P" * 20 not in out and "ceo@example.com" in out


def test_combolist_rule_still_fires_on_a_real_looking_list_and_not_on_prose():
    from darklens.rules.engine import run_rules
    listing = "\n".join(f"user{i}@example.com:Passw0rd{i}" for i in range(6))
    assert any(r.id == "DL-CRD-001" for r, _ in run_rules(listing))
    assert not any(r.id == "DL-CRD-001" for r, _ in run_rules("Meet at 10:30, then lunch with a@b.com: see you"))


# ---------------- long text is cut safely and says so ----------------

def test_long_text_is_scored_on_its_start_and_marked_truncated():
    long = "Selling initial access to a telecom VPN, price 2 XMR. " + "filler " * 3000
    a = pipeline.analyse(Item(source="m", kind="post", title="", text=long), [], [], CLF)
    assert a.truncated is True and a.score > 0
    short = pipeline.analyse(Item(source="m", kind="post", title="", text="Selling initial access, price 2 XMR"), [], [], CLF)
    assert short.truncated is False


def test_watchlist_and_indicators_still_see_the_whole_long_text():
    long = "nothing interesting here. " * 400 + " Attackers exploit a ScreenConnect flaw. contact leak@example.com " + "x" * 50
    a = pipeline.analyse(Item(source="m", kind="post", title="", text=long), [], ["leak@example.com"], CLF, ["screenconnect"])
    names = [s.name for s in a.signals]
    assert a.truncated and "Watchlist product match" in names and "Watchlist email match" in names
    assert "leak@example.com" in a.iocs["email"]


# ---------------- odd text never crashes the analyser ----------------

@pytest.mark.parametrize("text", ["", " ", "\n\t", "\x00", "💀", "‮", "a퟿b", "SELLING EXPLOIT", "ｓｅｌｌｉｎｇ ｅｘｐｌｏｉｔ",
                                  "<script>alert(1)</script>", "'; DROP TABLE alerts; --", "%s %d {0} ${x}", "\\x41\\u0041"])
def test_odd_text_gives_a_valid_result(text):
    a = pipeline.analyse(Item(source="m", kind="post", title=text, text=text), ["example.com"], ["a@example.com"], CLF, ["fortinet"])
    assert 0 <= a.score <= 100 and a.severity in ("low", "medium", "high", "critical") and a.category


def test_empty_text_is_not_an_alert():
    a = pipeline.analyse(Item(source="m", kind="post", title="", text=""), [], [], CLF)
    assert a.score == 0 and not a.signals


# ---------------- the API ----------------

@pytest.mark.parametrize("body", [{}, {"text": None}, {"text": 5}, {"text": ["a"]}, {"text": "x" * 20001}, {"title": "t"},
                                  {"text": "ok", "title": "t" * 5000}])
def test_analyse_rejects_bad_bodies_without_crashing(client, body):
    assert client.post("/api/analyse", json=body).status_code == 422


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b'{"text":', b"\xff\xfe\x00"])
def test_analyse_rejects_malformed_payloads(client, raw):
    r = client.post("/api/analyse", content=raw, headers={"Content-Type": "application/json"})
    assert r.status_code in (400, 422)


def test_analyse_accepts_the_largest_allowed_text_quickly(client):
    t = time.perf_counter()
    r = client.post("/api/analyse", json={"text": HOSTILE["dots"], "title": ""})
    assert r.status_code == 200 and r.json()["truncated"] is True and time.perf_counter() - t < 3


def test_analyse_empty_text_is_422_or_a_zero_score(client):
    r = client.post("/api/analyse", json={"text": "", "title": ""})
    assert r.status_code == 422 or r.json()["score"] == 0


@pytest.mark.parametrize("query", ["limit=abc", "limit=1.5", "offset=abc", "limit=99999999999999999999", "offset=99999999999999999999"])
def test_bad_numbers_in_alert_queries_are_422_not_500(client, query):
    assert client.get(f"/api/alerts?{query}").status_code in (200, 422)


@pytest.mark.parametrize("query", ["severity=nope", "category=nope", "data=weird", "severity=&category=&q=", "q=" + "a" * 5000,
                                   "q=%E2%80%AE", "q=%F0%9F%92%80", "severity=low&severity=high"])
def test_odd_filters_return_a_list(client, query):
    r = client.get(f"/api/alerts?{query}")
    assert r.status_code == 200 and isinstance(r.json(), list) and "x-total-count" in r.headers


@pytest.mark.parametrize("path", ["/api/alerts?q=%00", "/api/alerts/%00"])
def test_nul_characters_are_refused_with_400(client, path):
    """Postgres cannot store a NUL, and it used to be a 500 there; it is now a plain 400 on every database."""
    assert client.get(path).status_code == 400


def test_unknown_filter_values_match_nothing_rather_than_everything(client):
    assert client.get("/api/alerts?severity=nope").json() == []
    assert client.get("/api/alerts?category=nope").json() == []


@pytest.mark.parametrize("path", ["/api/alerts/nope", "/api/alerts/..%2f..%2fetc%2fpasswd", "/api/alerts/" + "a" * 3000,
                                  "/api/alerts/nope/evidence", "/api/alerts/%27%20OR%201=1--"])
def test_unknown_or_hostile_alert_ids_are_404(client, path):
    assert client.get(path).status_code in (404, 422)


def test_feedback_on_unknown_alert_and_bad_verdicts(client):
    assert client.post("/api/alerts/nope/feedback", json={"verdict": "correct", "category": ""}).status_code == 404
    first = client.get("/api/alerts?limit=1").json()[0]["item_id"]
    assert client.post(f"/api/alerts/{first}/feedback", json={"verdict": "maybe", "category": ""}).status_code == 400
    assert client.post(f"/api/alerts/{first}/feedback", json={"verdict": "wrong", "category": "nonsense"}).status_code == 400
    assert client.post(f"/api/alerts/{first}/feedback", json={}).status_code == 422


@pytest.mark.parametrize("kind,value", [
    ("domain", "Example.COM"), ("domain", "example.com."), ("domain", " example.com "), ("domain", "exa mple.com"), ("domain", "-bad.com"),
    ("domain", "bad-.com"), ("domain", "a..com"), ("domain", "http://example.com"), ("domain", "example.com/path"), ("domain", "münchen.de"),
    ("domain", "例え.jp"), ("domain", "x" * 64 + ".com"), ("domain", "1.2.3.4"), ("email", "A@B.CO"), ("email", "a b@c.com"),
    ("email", "a@@b.com"), ("email", "@b.com"), ("email", "a@b"), ("product", "c++"), ("product", ".net"), ("product", "log4j"),
    ("product", "a b c"), ("product", "x" * 61), ("product", "-bad"), ("product", "bad-"), ("product", "tab\tname"), ("product", "💀💀💀"),
    ("product", "ünïcode"), ("product", "%s%s%s"), ("product", "a'; --"), ("PRODUCT", "fortinet"), ("", "x"), ("domain", None)])
def test_watchlist_never_crashes_and_only_accepts_clean_values(client, kind, value):
    r = client.post("/api/watchlist", json={"kind": kind, "value": value})
    assert r.status_code in (200, 400, 422)
    if r.status_code == 200:
        stored = {(w["kind"], w["value"]) for w in r.json()}
        assert all(v == v.strip().lower() and v for _, v in stored)


def test_watchlist_dedupes_and_is_case_insensitive(client):
    for v in ("Fortinet", "FORTINET", " fortinet "):
        assert client.post("/api/watchlist", json={"kind": "product", "value": v}).status_code == 200
    assert [w for w in client.get("/api/watchlist").json() if w["value"] == "fortinet"] == [{"kind": "product", "value": "fortinet"}]


@pytest.mark.parametrize("name", ["c++", ".net", "log4j", "node.js", "7-zip", "d-link"])
def test_awkward_product_names_match_as_whole_words(name):
    a = pipeline.analyse(Item(source="m", kind="post", title="", text=f"Attackers exploit a flaw in {name} to breach servers"),
                         [], [], CLF, [name])
    assert "Watchlist product match" in [s.name for s in a.signals]
    b = pipeline.analyse(Item(source="m", kind="post", title="", text=f"Attackers exploit a flaw in x{name}y to breach servers"),
                         [], [], CLF, [name])
    assert "Watchlist product match" not in [s.name for s in b.signals]


def test_rescore_with_special_characters_does_not_match_everything(client):
    con = client.module.con()
    pipeline.run(items=[Item(source="m", kind="post", title="A", text="Extortion group claims theft of records, 100% done"),
                        Item(source="m", kind="post", title="B", text="Extortion group claims theft of customer records")], con=con)
    for value in ("100%", "a_b", "c\\d"):
        out = pipeline.rescore(con, contains=value)
        assert out["items"] <= 1


def test_empty_database_endpoints_do_not_crash(client):
    con = client.module.con()
    con.execute("DELETE FROM alerts")
    con.execute("DELETE FROM iocs")
    con.commit()
    assert client.get("/api/alerts").json() == [] and client.get("/api/alerts").headers["x-total-count"] == "0"
    stats = client.get("/api/stats").json()
    assert stats["alerts"] == 0 and stats["by_severity"] == {}
    assert client.get("/api/graph").status_code == 200
    assert client.get("/api/export/alerts.csv").status_code == 200
    assert client.get("/api/export/stix.json").status_code == 200
    assert client.get("/api/feedback/summary").json()["total"] == 0


@pytest.mark.parametrize("method,path", [("PUT", "/api/alerts"), ("DELETE", "/api/watchlist"), ("PATCH", "/api/stats"), ("POST", "/api/stats")])
def test_unsupported_methods_are_405(client, method, path):
    assert client.request(method, path).status_code == 405


def test_unknown_paths_are_404_and_head_health_works(client):
    assert client.get("/api/nope").status_code == 404
    assert client.head("/api/health").status_code == 200


@pytest.mark.parametrize("kind,value,ok", [
    ("domain", "-bad.com", False), ("domain", "bad-.com", False), ("domain", "a" * 64 + ".com", False), ("domain", "a" * 63 + ".com", True),
    ("domain", "x-y.example.co.uk", True), ("product", "c++", True), ("product", "c#", False), ("product", "asp.net", True),
    ("product", "-bad", False), ("product", "bad-", False)])
def test_watchlist_validation_boundaries(client, kind, value, ok):
    assert (client.post("/api/watchlist", json={"kind": kind, "value": value}).status_code == 200) == ok
