"""Alert rules written as a sentence, and the Slack / Discord / Teams connectors (added in 0.4.0)."""
import re
import socket

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import accounts, alert_rules, pipeline, workspace
from darklens.models import Item

PUBLIC_IP = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AUTH_DEV_LINKS", "1")
    monkeypatch.setenv("RATE_LIMIT_WRITE_PER_MIN", "0")
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


def sign_in(client, email="r@example.com"):
    r = client.post("/api/auth/request", json={"email": email})
    token = re.search(r"token=([\w-]+)", r.json()["dev_link"]).group(1)
    return {"Authorization": f"Bearer {client.post('/api/auth/verify', json={'token': token}).json()['token']}"}


def put(client, *items):
    pipeline.run(items=list(items), con=client.module.con())


# ---------------- the parser ----------------

@pytest.mark.parametrize("prompt, expect", [
    ("alert me for any php2shell vulnerability", {"products": ["php"], "attacks": ["rce"]}),
    ("any PHP to shell vulnerability in WordPress", {"products": ["wordpress", "php"], "attacks": ["rce"]}),
    ("ransomware attacks on hospitals, critical only", {"keywords": ["hospitals"], "categories": ["ransomware_leak"], "min_severity": "critical"}),
    ("anything about CVE-2024-4577", {"cves": ["CVE-2024-4577"]}),
    ("leaked logins for acme.com", {"categories": ["credential_dump"], "domains": ["acme.com"]}),
    ("sql injection in moveit", {"products": ["moveit"], "attacks": ["sqli"]}),
    ("Fortinet bugs exploited in the wild", {"products": ["fortinet"], "categories": ["known_exploited"]}),
    ("phishing kits targeting banks", {"keywords": ["banks"], "categories": ["phishing_kit"]}),
    ("tell me about anything serious affecting okta", {"products": ["okta"], "min_severity": "high"}),
    ("node.js supply chain", {"products": ["node.js"]}),
])
def test_sentences_become_the_expected_rule(prompt, expect):
    spec = alert_rules.parse_prompt(prompt)
    for k, v in expect.items():
        assert spec[k] == v, (k, spec)
    assert not alert_rules.is_empty(spec)


@pytest.mark.parametrize("prompt", ["", "   ", "alert me", "please tell me about anything", "x" * 5000, "\x00\x01", "🙂🙂🙂"])
def test_empty_or_hostile_sentences_parse_to_nothing_without_crashing(prompt):
    spec = alert_rules.parse_prompt(prompt)
    assert set(spec) == set(alert_rules.empty_spec())
    assert alert_rules.is_empty(spec) or len(spec["keywords"]) <= 5


def test_a_spec_from_the_browser_is_cleaned():
    spec = alert_rules.clean_spec({"products": ["WordPress", "", 5, "x" * 500], "attacks": ["rce", "nonsense"], "cves": ["cve-2024-1234", "CVE-bad"],
                                   "domains": ["Acme.COM", "not a domain"], "min_severity": "extreme", "evil": ["x"]})
    assert spec["products"][0] == "wordpress" and all(len(p) <= 60 for p in spec["products"])
    assert spec["attacks"] == ["rce"] and spec["cves"] == ["CVE-2024-1234"] and spec["domains"] == ["acme.com"]
    assert spec["min_severity"] == "medium" and "evil" not in spec


def test_every_group_must_match():
    spec = alert_rules.parse_prompt("any PHP to shell vulnerability in WordPress")
    assert alert_rules.match(spec, "critical flaw in a wordpress plugin allows remote code execution", "known_exploited", "high")
    assert alert_rules.match(spec, "wordpress 6.7 is out with a new editor", "benign", "high") is None  # no attack words
    assert alert_rules.match(spec, "remote code execution in exchange server", "known_exploited", "high") is None  # wrong product
    leak = alert_rules.parse_prompt("leaked logins for acme.com")
    assert alert_rules.match(leak, "combolist with acme.com credentials", "credential_dump", "high")
    assert alert_rules.match(leak, "acme.com opens a new office", "benign", "high") is None


def test_the_severity_floor_and_plurals():
    spec = alert_rules.parse_prompt("ransomware attacks on hospitals, critical only")
    assert alert_rules.match(spec, "lockbit claims st mary hospital", "ransomware_leak", "critical")
    assert alert_rules.match(spec, "lockbit claims st mary hospital", "ransomware_leak", "high") is None
    banks = alert_rules.parse_prompt("phishing kits targeting banks")
    assert alert_rules.match(banks, "new phishing page copies a bank login", "phishing_kit", "medium")


def test_the_summary_reads_as_a_sentence():
    s = alert_rules.describe(alert_rules.parse_prompt("leaked logins for acme.com, critical only"))
    assert s.startswith("Alert on ") and s.endswith("rated Critical.") and "acme.com" in s


# ---------------- the API ----------------

def test_parsing_needs_no_account_and_stores_nothing(client):
    r = client.post("/api/rules/parse", json={"prompt": "sql injection in moveit"})
    assert r.status_code == 200 and r.json()["spec"]["attacks"] == ["sqli"] and not r.json()["empty"]
    assert client.post("/api/rules/parse", json={"prompt": "x" * 301}).status_code == 422
    assert "rce" in client.get("/api/rules/vocabulary").json()["attacks"]


def test_saving_listing_and_deleting_rules(client):
    h = sign_in(client)
    assert client.post("/api/workspace/rules", json={"prompt": "hello"}).status_code == 401
    assert client.post("/api/workspace/rules", json={"prompt": "please tell me"}, headers=h).status_code == 400  # nothing to watch
    ws = client.post("/api/workspace/rules", json={"prompt": "sql injection in moveit"}, headers=h).json()
    assert len(ws["rules"]) == 1 and ws["rules"][0]["summary"].startswith("Alert on")
    edited = {**ws["rules"][0]["spec"], "products": ["moveit", "progress"]}
    ws = client.post("/api/workspace/rules", json={"prompt": "moveit or progress sqli", "spec": edited}, headers=h).json()
    assert ws["rules"][1]["spec"]["products"] == ["moveit", "progress"]
    ws = client.delete(f"/api/workspace/rules/{ws['rules'][0]['id']}", headers=h).json()
    assert [r["prompt"] for r in ws["rules"]] == ["moveit or progress sqli"]


def test_one_person_cannot_delete_another_persons_rule(client):
    a, b = sign_in(client, "a@example.com"), sign_in(client, "b@example.com")
    rid = client.post("/api/workspace/rules", json={"prompt": "ransomware"}, headers=a).json()["rules"][0]["id"]
    client.delete(f"/api/workspace/rules/{rid}", headers=b)
    assert len(client.get("/api/me", headers=a).json()["workspace"]["rules"]) == 1


def test_the_rule_limit(client, monkeypatch):
    monkeypatch.setattr(alert_rules, "MAX_RULES", 2)
    h = sign_in(client)
    for p in ("ransomware", "phishing"):
        assert client.post("/api/workspace/rules", json={"prompt": p}, headers=h).status_code == 200
    assert client.post("/api/workspace/rules", json={"prompt": "malware"}, headers=h).status_code == 400


def test_a_rule_fills_my_alerts_and_says_why(client):
    h = sign_in(client)
    put(client,
        Item(source="cisa-kev", kind="post", title="PHP CGI argument injection", url="https://example.org/kev/1",
             text="PHP contains an argument injection flaw that allows remote code execution. Known to be exploited in the wild."),
        Item(source="rss", kind="post", title="PHP 9 release date announced", text="The PHP team announced the release schedule."))
    client.post("/api/workspace/rules", json={"prompt": "any php2shell vulnerability"}, headers=h)
    feed = client.get("/api/workspace/alerts", headers=h).json()
    assert [a["title"] for a in feed] == ["PHP CGI argument injection"]
    a = feed[0]
    assert a["rules"][0]["prompt"] == "any php2shell vulnerability" and "php" in a["rules"][0]["evidence"]
    assert a["url"] == "https://example.org/kev/1"


def test_my_alerts_are_sorted_most_serious_first(client):
    h = sign_in(client)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
    put(client,
        Item(source="rss", kind="post", title="ScreenConnect news", text="ScreenConnect announces a new office"),
        Item(source="rss", kind="post", title="ScreenConnect exploited", text="Attackers exploit a ScreenConnect flaw in a ransomware attack"))
    feed = client.get("/api/workspace/alerts", headers=h).json()
    ranks = [workspace.SEVERITY_RANK[a["severity"]] for a in feed]
    assert ranks == sorted(ranks, reverse=True) and feed[0]["title"] == "ScreenConnect exploited"


# ---------------- connectors ----------------

@pytest.mark.parametrize("kind, url, ok", [
    ("slack", "https://hooks.slack.com/services/T0/B0/xyz", True),
    ("slack", "https://example.com/services/x", False),
    ("discord", "https://discord.com/api/webhooks/1/abc", True),
    ("discord", "https://discord.com/channels/1", False),
    ("teams", "https://acme.webhook.office.com/webhookb2/x", True),
    ("teams", "https://evil.example/teams", False),
    ("slack", "http://hooks.slack.com/services/x", False),
    ("pager", "https://hooks.slack.com/services/x", False),
])
def test_connector_addresses_must_belong_to_the_service(monkeypatch, kind, url, ok):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    assert (accounts.check_connector_url(kind, url) is None) == ok


def test_connectors_are_masked_tested_and_removed(client, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    sent = []
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text, kind="": sent.append((kind, text)))
    h = sign_in(client)
    url = "https://discord.com/api/webhooks/123456789/secret-token-that-must-not-be-shown"
    ws = client.put("/api/workspace/connectors/discord", json={"url": url, "min_severity": "medium"}, headers=h).json()
    (c,) = ws["connectors"]
    assert c["kind"] == "discord" and c["min_severity"] == "medium" and "secret-token" not in c["url"]
    assert client.put("/api/workspace/connectors/slack", json={"url": url}, headers=h).status_code == 400
    assert client.post("/api/workspace/connectors/discord/test", headers=h).json() == {"ok": True} and sent[0][0] == "discord"
    assert client.patch("/api/workspace/connectors/discord", json={"min_severity": "critical"}, headers=h).json()["connectors"][0]["min_severity"] == "critical"
    assert client.delete("/api/workspace/connectors/discord", headers=h).json()["connectors"] == []


def test_connectors_deliver_new_matches_once_worst_first(client, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    sent = []
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text, kind="": sent.append((kind, text)))
    h = sign_in(client)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
    client.put("/api/workspace/connectors/slack", json={"url": "https://hooks.slack.com/services/T/B/x", "min_severity": "low"}, headers=h)
    put(client,
        Item(source="rss", kind="post", title="ScreenConnect news", text="ScreenConnect announces a new office", url="https://example.org/a"),
        Item(source="rss", kind="post", title="ScreenConnect exploited", text="Attackers exploit a ScreenConnect flaw in a ransomware attack",
             url="https://example.org/b"))
    ws = accounts.all_workspaces(client.module.con())[0]
    assert workspace.dispatch_connectors(client.module.con(), ws) == 2
    assert [k for k, _ in sent] == ["slack", "slack"] and "ScreenConnect exploited" in sent[0][1]
    assert "Read the original report: https://example.org/b" in sent[0][1]
    assert workspace.dispatch_connectors(client.module.con(), ws) == 0  # each alert goes out once


def test_deleting_the_account_removes_rules_and_connectors(client, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    h = sign_in(client)
    client.post("/api/workspace/rules", json={"prompt": "ransomware"}, headers=h)
    client.put("/api/workspace/connectors/slack", json={"url": "https://hooks.slack.com/services/T/B/x"}, headers=h)
    assert client.delete("/api/account", headers=h).status_code == 200
    con = client.module.con()
    assert con.execute("SELECT COUNT(*) AS n FROM ws_rules").fetchone()["n"] == 0
    assert con.execute("SELECT COUNT(*) AS n FROM ws_connectors").fetchone()["n"] == 0


@pytest.mark.parametrize("prompt", ["a." * 200, "a-" * 200 + "!", "a" * 64 + "@" + "b." * 150, "cve-2024-" + "1" * 300, "x2shell " * 60])
def test_hostile_sentences_parse_quickly(prompt):
    import time
    start = time.perf_counter()
    alert_rules.parse_prompt(prompt)
    assert time.perf_counter() - start < 0.5
