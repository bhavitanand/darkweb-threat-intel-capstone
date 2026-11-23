"""Accounts, private workspaces, API keys, the digest, the alert webhook and the mailer."""
import re
import socket
import threading

import pytest
from fastapi.testclient import TestClient
from helpers import load_app

from darklens import accounts, ingest, mailer, pipeline, workspace
from darklens.models import Item
from darklens.store import db

PUBLIC_IP = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AUTH_DEV_LINKS", "1")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://app.example")
    monkeypatch.setenv("RATE_LIMIT_WRITE_PER_MIN", "0")  # the per-address limit has its own tests; these make dozens of writes
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        c.module = module
        yield c


def sign_in(client, email="a@example.com"):
    r = client.post("/api/auth/request", json={"email": email})
    assert r.status_code == 200, r.text
    token = re.search(r"token=([\w-]+)", r.json()["dev_link"]).group(1)
    v = client.post("/api/auth/verify", json={"token": token})
    assert v.status_code == 200, v.text
    return {"Authorization": f"Bearer {v.json()['token']}"}


def put_items(client, *items):
    pipeline.run(items=list(items), con=client.module.con())


def breach_item(org="Acme", title=None, text=None, **kw):
    return Item(source="rss", kind="post", title=title or f"{org} data breach",
                text=text or f"Hackers breached {org} and posted customer records. Attackers exploit a ScreenConnect flaw.", **kw)


# ---------------- requesting a link ----------------

def test_without_email_set_up_and_without_dev_links_signing_in_is_unavailable(monkeypatch):
    monkeypatch.delenv("AUTH_DEV_LINKS", raising=False)
    for k in ("BREVO_API_KEY", "SMTP_HOST"):
        monkeypatch.delenv(k, raising=False)
    module = load_app(monkeypatch)
    with TestClient(module.app) as c:
        assert c.post("/api/auth/request", json={"email": "a@example.com"}).status_code == 503


@pytest.mark.parametrize("email", ["", "nope", "a@b", "a b@example.com", "a@@example.com", "@example.com", "a@example..com", "x" * 300 + "@example.com",
                                   "a@example.com\nBcc: x@y.com", "a@example.com, b@example.com", "<script>@example.com", None, 5, ["a@example.com"]])
def test_bad_addresses_are_refused(client, email):
    assert client.post("/api/auth/request", json={"email": email}).status_code in (400, 422)


def test_the_answer_does_not_reveal_whether_an_account_exists(client):
    sign_in(client, "known@example.com")
    a = client.post("/api/auth/request", json={"email": "known@example.com"}).json()
    b = client.post("/api/auth/request", json={"email": "stranger@example.com"}).json()
    assert a["message"] == b["message"] and set(a) == set(b)


def test_asking_too_often_gets_the_same_answer_but_no_link(client):
    got = [client.post("/api/auth/request", json={"email": "spam@example.com"}).json() for _ in range(accounts.MAX_LOGINS_PER_EMAIL_PER_HOUR + 3)]
    assert sum("dev_link" in g for g in got) == accounts.MAX_LOGINS_PER_EMAIL_PER_HOUR
    assert len({g["message"] for g in got}) == 1


def test_email_case_and_spaces_do_not_make_a_second_account(client):
    h1 = sign_in(client, "Mixed@Example.com")
    h2 = sign_in(client, "  mixed@example.COM ")
    assert client.get("/api/me", headers=h1).json()["email"] == client.get("/api/me", headers=h2).json()["email"] == "mixed@example.com"
    ids = {w["id"] for w in accounts.all_workspaces(client.module.con())}
    assert len(ids) == 1


def test_tokens_are_stored_only_as_hashes(client):
    r = client.post("/api/auth/request", json={"email": "h@example.com"}).json()
    token = re.search(r"token=([\w-]+)", r["dev_link"]).group(1)
    con = client.module.con()
    assert con.execute("SELECT 1 AS x FROM login_tokens WHERE token_hash=?", (token,)).fetchone() is None
    session = client.post("/api/auth/verify", json={"token": token}).json()["token"]
    assert con.execute("SELECT 1 AS x FROM sessions WHERE token_hash=?", (session,)).fetchone() is None
    assert con.execute("SELECT 1 AS x FROM sessions WHERE token_hash=?", (accounts.hash_secret(session),)).fetchone() is not None


# ---------------- using a link ----------------

def test_a_link_works_once(client):
    token = re.search(r"token=([\w-]+)", client.post("/api/auth/request", json={"email": "o@example.com"}).json()["dev_link"]).group(1)
    assert client.post("/api/auth/verify", json={"token": token}).status_code == 200
    assert client.post("/api/auth/verify", json={"token": token}).status_code == 400


def test_an_expired_link_is_refused(client):
    token = re.search(r"token=([\w-]+)", client.post("/api/auth/request", json={"email": "e@example.com"}).json()["dev_link"]).group(1)
    con = client.module.con()
    con.execute("UPDATE login_tokens SET expires_at='2000-01-01T00:00:00Z'")
    con.commit()
    assert client.post("/api/auth/verify", json={"token": token}).status_code == 400


@pytest.mark.parametrize("token", ["", "short", "x" * 20, "x" * 500, "' OR 1=1 --" + "a" * 30, "../../etc/passwd" + "a" * 30, "%00" * 20, None, 5])
def test_garbage_tokens_are_refused(client, token):
    assert client.post("/api/auth/verify", json={"token": token}).status_code in (400, 422)


def test_a_session_works_until_it_ends_or_expires(client):
    h = sign_in(client)
    assert client.get("/api/me", headers=h).status_code == 200
    con = client.module.con()
    con.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00Z'")
    con.commit()
    assert client.get("/api/me", headers=h).status_code == 401


@pytest.mark.parametrize("header", [None, "", "Bearer", "Bearer ", "Bearer nope", "bearer " + "a" * 40, "Basic abc", "Bearer " + "a" * 500, "Token x"])
def test_missing_or_wrong_credentials_are_401(client, header):
    for path in ("/api/me", "/api/workspace", "/api/workspace/alerts"):
        r = client.get(path, headers={"Authorization": header} if header is not None else {})
        assert r.status_code == 401, path


def test_logging_out_ends_the_session(client):
    h = sign_in(client)
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/me", headers=h).status_code == 401


def test_only_the_newest_sessions_are_kept(client, monkeypatch):
    monkeypatch.setattr(accounts, "MAX_LOGINS_PER_EMAIL_PER_HOUR", 100)
    first = sign_in(client, "many@example.com")
    for _ in range(accounts.MAX_SESSIONS_PER_USER + 2):
        sign_in(client, "many@example.com")
    assert client.get("/api/me", headers=first).status_code == 401


# ---------------- the private watchlist ----------------

def test_watchlist_entries_are_validated_cleaned_and_deduplicated(client):
    h = sign_in(client)
    for kind, value in (("domain", " Acme.COM "), ("email", "Boss@Acme.com"), ("product", "ScreenConnect"), ("product", "screenconnect")):
        assert client.post("/api/workspace/watch", json={"kind": kind, "value": value}, headers=h).status_code == 200
    entries = client.get("/api/workspace", headers=h).json()["entries"]
    assert entries == [{"kind": "domain", "value": "acme.com"}, {"kind": "email", "value": "boss@acme.com"}, {"kind": "product", "value": "screenconnect"}]
    for kind, value in (("domain", "not a domain"), ("domain", "-bad.com"), ("email", "a@b"), ("product", "ab"), ("product", "<script>"), ("url", "x.com"), ("", ""), ("domain", None)):
        assert client.post("/api/workspace/watch", json={"kind": kind, "value": value}, headers=h).status_code in (400, 422), (kind, value)


def test_entries_can_be_removed_and_the_cap_holds(client, monkeypatch):
    h = sign_in(client)
    monkeypatch.setattr(accounts, "WORKSPACE_WATCH_MAX", 3)
    for n in ("alpha", "bravo", "charlie"):
        assert client.post("/api/workspace/watch", json={"kind": "product", "value": n}, headers=h).status_code == 200
    assert client.post("/api/workspace/watch", json={"kind": "product", "value": "delta"}, headers=h).status_code == 400
    assert client.post("/api/workspace/watch", json={"kind": "product", "value": "alpha"}, headers=h).status_code == 200
    out = client.delete("/api/workspace/watch", params={"kind": "product", "value": "alpha"}, headers=h).json()
    assert [e["value"] for e in out["entries"]] == ["bravo", "charlie"]
    assert client.delete("/api/workspace/watch", params={"kind": "product", "value": "nothing"}, headers=h).status_code == 200


def test_two_people_never_see_each_others_entries_or_alerts(client):
    a, b = sign_in(client, "a@example.com"), sign_in(client, "b@example.com")
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=a)
    put_items(client, breach_item("Acme"))
    assert client.get("/api/workspace", headers=b).json()["entries"] == []
    assert client.get("/api/workspace/alerts", headers=b).json() == []
    mine = client.get("/api/workspace/alerts", headers=a).json()
    assert mine and mine[0]["matched"] == ["screenconnect"]


def test_a_private_watchlist_does_not_change_the_global_alerts(client):
    put_items(client, breach_item("Acme"))
    before = {r["item_id"]: r["score"] for r in client.get("/api/alerts?limit=5000").json()}
    h = sign_in(client)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
    assert client.get("/api/workspace/alerts", headers=h).json()
    after = {r["item_id"]: r["score"] for r in client.get("/api/alerts?limit=5000").json()}
    assert before == after
    assert [w for w in client.get("/api/watchlist").json() if w["value"] == "screenconnect"] == []  # and the public list is untouched


def test_personal_alerts_use_only_that_workspaces_entries_and_hide_restricted_text(client):
    secret = "zebrafishcanary"
    put_items(client, Item(source="therecord", kind="post", title="Acme breach", text=f"Attackers breached Acme and posted customer records. {secret}",
                           meta={"no_redistribute": True}),
              Item(source="rss", kind="post", title="Unrelated", text="Weather today is mild and the football was great"))
    h = sign_in(client)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "acme"}, headers=h)
    rows = client.get("/api/workspace/alerts", headers=h).json()
    assert [r["title"] for r in rows] == ["Acme breach"]
    assert rows[0]["restricted"] is True and rows[0]["text"] == "" and secret not in str(rows)
    assert all({"item_id", "severity", "score", "category", "reasons", "matched"} <= set(r) for r in rows)


def test_a_workspace_with_no_entries_sees_nothing(client):
    put_items(client, breach_item())
    assert client.get("/api/workspace/alerts", headers=sign_in(client)).json() == []


def test_special_characters_in_entries_match_literally(client):
    put_items(client, breach_item("Acme", text="Customer records leaked, 100% of them. The c++ runtime and a_b were mentioned. Attackers breached it."))
    h = sign_in(client)
    for value in ("100%", "a_b", "c++"):
        client.post("/api/workspace/watch", json={"kind": "product", "value": value}, headers=h) if value != "100%" else None
    rows = client.get("/api/workspace/alerts", headers=h).json()
    assert all(r["title"] == "Acme data breach" for r in rows)


# ---------------- API keys ----------------

def test_api_keys_are_shown_once_read_only_and_revocable(client):
    h = sign_in(client)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
    put_items(client, breach_item("Acme"))
    made = client.post("/api/workspace/keys", json={"label": "  my   script  "}, headers=h).json()
    key = made["key"]
    assert key.startswith("dlk_") and made["label"] == "my script"
    listed = client.get("/api/workspace", headers=h).json()["api_keys"]
    assert listed and "key" not in listed[0] and key not in str(listed)
    assert client.module.con().execute("SELECT 1 AS x FROM api_keys WHERE key_hash=?", (key,)).fetchone() is None  # only the hash is stored
    ok = client.get("/api/workspace/alerts", headers={"X-API-Key": key})
    assert ok.status_code == 200 and ok.json()
    for path in ("/api/me", "/api/workspace"):
        assert client.get(path, headers={"X-API-Key": key}).status_code == 401  # a key reads alerts and nothing else
    assert client.post("/api/workspace/keys", json={"label": "x"}, headers={"X-API-Key": key}).status_code == 401
    assert client.delete(f"/api/workspace/keys/{made['id']}", headers=h).status_code == 200
    assert client.get("/api/workspace/alerts", headers={"X-API-Key": key}).status_code == 401


@pytest.mark.parametrize("key", ["", "nope", "dlk_", "dlk_" + "a" * 30, "dlk_" + "a" * 500, "' OR 1=1 --", None])
def test_invalid_api_keys_are_401_not_a_fallback_to_anything_else(client, key):
    h = {"X-API-Key": key} if key is not None else {}
    assert client.get("/api/workspace/alerts", headers=h).status_code == 401


def test_key_count_is_capped_and_other_workspaces_cannot_revoke_a_key(client):
    h, other = sign_in(client, "a@example.com"), sign_in(client, "b@example.com")
    ids = [client.post("/api/workspace/keys", json={"label": str(i)}, headers=h).json()["id"] for i in range(accounts.MAX_API_KEYS)]
    assert client.post("/api/workspace/keys", json={"label": "one too many"}, headers=h).status_code == 400
    client.delete(f"/api/workspace/keys/{ids[0]}", headers=other)
    assert len(client.get("/api/workspace", headers=h).json()["api_keys"]) == accounts.MAX_API_KEYS


# ---------------- settings and the webhook address ----------------

@pytest.mark.parametrize("url", ["http://hooks.example/x", "ftp://hooks.example/x", "https://127.0.0.1/x", "https://localhost/x", "https://192.168.1.5/x", "https://10.0.0.1/x",
                                 "https://169.254.169.254/latest/meta-data", "https://[::1]/x", "https://user:pw@hooks.example/x", "https://hooks.example:8443/x",
                                 "https://", "javascript:alert(1)", "https://hooks.example/" + "a" * 600, "not a url", "//hooks.example/x"])
def test_unsafe_webhook_addresses_are_refused(client, monkeypatch, url):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP if host == "hooks.example" else socket.getaddrinfo.__wrapped__(host, *a, **k)
                        if hasattr(socket.getaddrinfo, "__wrapped__") else [(socket.AF_INET, 1, 6, "", ("127.0.0.1", 443))])
    h = sign_in(client)
    assert client.put("/api/workspace/settings", json={"webhook_url": url}, headers=h).status_code in (400, 422)


def test_a_public_https_webhook_is_accepted_and_a_name_that_points_inside_is_not(client, monkeypatch):
    h = sign_in(client)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    assert client.put("/api/workspace/settings", json={"webhook_url": "https://hooks.slack.example/T/B/x"}, headers=h).json()["webhook_url"] == "https://hooks.slack.example/T/B/x"
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(socket.AF_INET, 1, 6, "", ("10.1.2.3", 443))])
    assert client.put("/api/workspace/settings", json={"webhook_url": "https://sneaky.example/x"}, headers=h).status_code == 400
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: (_ for _ in ()).throw(socket.gaierror()))
    assert client.put("/api/workspace/settings", json={"webhook_url": "https://missing.example/x"}, headers=h).status_code == 400


def test_clearing_the_webhook_and_changing_choices(client, monkeypatch):
    h = sign_in(client)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    client.put("/api/workspace/settings", json={"webhook_url": "https://h.example/x", "digest": "weekly", "notify_min": "medium"}, headers=h)
    out = client.put("/api/workspace/settings", json={"webhook_url": ""}, headers=h).json()
    assert out["webhook_url"] == "" and out["digest"] == "weekly" and out["notify_min"] == "medium"  # untouched fields stay
    for body in ({"digest": "hourly"}, {"notify_min": "everything"}, {"digest": ""}, {"notify_min": None, "digest": "yes"}):
        assert client.put("/api/workspace/settings", json=body, headers=h).status_code == 400


def test_a_webhook_is_checked_again_when_sending(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(socket.AF_INET, 1, 6, "", ("10.0.0.9", 443))])
    with pytest.raises(ValueError):
        workspace.post_webhook("https://was-fine-yesterday.example/x", "hello")


# ---------------- the digest ----------------

class Outbox:
    def __init__(self):
        self.sent = []

    def __call__(self, to, subject, body):
        self.sent.append((to, subject, body))


def setup_digest(client, monkeypatch):
    h = sign_in(client)  # sign in first: once the mailer is stubbed, the link goes to the outbox, not the response
    out = Outbox()
    monkeypatch.setattr(mailer, "configured", lambda: True)
    monkeypatch.setattr(mailer, "send", out)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
    return h, out


def test_the_digest_covers_only_new_items_once(client, monkeypatch):
    h, out = setup_digest(client, monkeypatch)
    put_items(client, breach_item("Acme"))
    preview = client.get("/api/workspace/digest/preview", headers=h).json()
    assert preview["count"] == 1 and "Acme" in preview["body"] and out.sent == []  # a preview sends and marks nothing
    assert client.get("/api/workspace/digest/preview", headers=h).json()["count"] == 1
    assert client.post("/api/workspace/digest/send", headers=h).json() == {"sent": True, "count": 1}
    assert out.sent[0][0] == "a@example.com" and "Acme" in out.sent[0][2]
    assert client.post("/api/workspace/digest/send", headers=h).json() == {"sent": False, "count": 0}
    put_items(client, breach_item("Globex"))
    assert client.get("/api/workspace/digest/preview", headers=h).json()["count"] == 1  # only the new one


def test_a_digest_leaks_no_restricted_text_and_no_header_injection(client, monkeypatch):
    h, out = setup_digest(client, monkeypatch)
    put_items(client, Item(source="therecord", kind="post", title="Acme\r\nBcc: evil@example.com breach", text="Attackers breached Acme (zebrafishcanary) via a ScreenConnect flaw",
                           meta={"no_redistribute": True}))
    client.post("/api/workspace/digest/send", headers=h)
    to, subject, body = out.sent[0]
    assert "zebrafishcanary" not in body and "\n" not in subject and "\r" not in body and "Bcc" not in subject
    assert "https://app.example/#/workspace" in body


def test_sending_a_digest_without_email_set_up_is_a_clear_error(client):
    assert client.post("/api/workspace/digest/send", headers=sign_in(client)).status_code in (503,)


def test_a_failing_mail_provider_does_not_mark_items_as_sent(client, monkeypatch):
    h, _ = setup_digest(client, monkeypatch)
    put_items(client, breach_item("Acme"))
    monkeypatch.setattr(mailer, "send", lambda *a: (_ for _ in ()).throw(mailer.MailError("down")))
    assert client.post("/api/workspace/digest/send", headers=h).status_code == 503
    assert client.get("/api/workspace/digest/preview", headers=h).json()["count"] == 1  # still waiting


@pytest.mark.parametrize("digest,last,hours,due", [("off", "", 0, False), ("daily", "", 0, True), ("daily", "now", 5, False), ("daily", "now", 23, True),
                                                   ("weekly", "now", 24 * 3, False), ("weekly", "now", 24 * 7, True), ("daily", "garbage", 0, True), (None, "", 0, False), ("bogus", "", 0, False)])
def test_when_a_digest_is_due(digest, last, hours, due):
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    stamp = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ") if last == "now" else last
    assert workspace.digest_due({"digest": digest, "digest_sent_at": stamp}, now) is due


def test_the_scheduled_run_sends_due_digests_and_survives_one_failing(client, monkeypatch):
    h1, h2 = sign_in(client, "one@example.com"), sign_in(client, "two@example.com")
    out = Outbox()
    monkeypatch.setattr(mailer, "configured", lambda: True)
    monkeypatch.setattr(mailer, "send", out)
    for h in (h1, h2):
        client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
        client.put("/api/workspace/settings", json={"digest": "daily"}, headers=h)
    put_items(client, breach_item("Acme"))
    first_call = {"n": 0}
    real = workspace.send_digest

    def flaky(con, ws, email):
        first_call["n"] += 1
        if first_call["n"] == 1:
            raise mailer.MailError("down")
        return real(con, ws, email)
    monkeypatch.setattr(workspace, "send_digest", flaky)
    res = workspace.run_scheduled(client.module.con())
    assert res["digests"] == 1 and len(out.sent) == 1  # one failed, the other still went out


def test_a_collection_runs_the_workspace_alerts(client, monkeypatch):
    seen = []
    monkeypatch.setattr(workspace, "run_scheduled", lambda con: seen.append(1) or {})
    ingest.run_ingest(live=False, con=client.module.con())
    assert seen == [1]
    monkeypatch.setattr(workspace, "run_scheduled", lambda con: (_ for _ in ()).throw(RuntimeError("boom")))
    assert ingest.run_ingest(live=False, con=client.module.con())["ok"] is True  # private alerts never break a collection


# ---------------- the alert webhook ----------------

def setup_webhook(client, monkeypatch, notify_min="medium"):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: PUBLIC_IP)
    h = sign_in(client)
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=h)
    client.put("/api/workspace/settings", json={"webhook_url": "https://hooks.example/x", "notify_min": notify_min}, headers=h)
    return h


def ws_of(client):
    return accounts.all_workspaces(client.module.con())[0]


def test_webhook_alerts_go_out_once_and_respect_the_level(client, monkeypatch):
    sent = []
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: sent.append(text))
    h = setup_webhook(client, monkeypatch, "high")
    # a passing mention of a watched product is only a Low hint
    put_items(client, Item(source="rss", kind="post", title="ScreenConnect news", text="ScreenConnect announces a new office and a partner programme"))
    mild = workspace.personal_alerts(client.module.con(), ws_of(client)["id"])
    assert mild and mild[0]["severity"] == "low"
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 0 and sent == []  # below the chosen level
    client.put("/api/workspace/settings", json={"notify_min": "low"}, headers=h)
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 1 and "ScreenConnect news" in sent[0]
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 0  # not again


def test_a_refused_alert_is_skipped_but_an_outage_is_retried(client, monkeypatch):
    setup_webhook(client, monkeypatch, "low")
    put_items(client, breach_item("Acme"))

    class Resp:
        def __init__(self, code): self.status_code = code

    class HTTPError(Exception):
        def __init__(self, code):
            super().__init__(str(code))
            self.response = Resp(code)
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: (_ for _ in ()).throw(HTTPError(503)))
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 0
    sent = []
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: sent.append(text))
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 1  # retried after the outage
    put_items(client, breach_item("Globex"))
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: (_ for _ in ()).throw(HTTPError(400)))
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 0
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: sent.append(text))
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == 0  # the refused one is not retried forever


def test_a_flood_is_capped_with_one_summary(client, monkeypatch):
    sent = []
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: sent.append(text))
    setup_webhook(client, monkeypatch, "low")
    put_items(client, *[breach_item(f"Company{i}") for i in range(workspace.WEBHOOK_MAX_PER_RUN + 4)])
    assert workspace.dispatch_webhook(client.module.con(), ws_of(client)) == workspace.WEBHOOK_MAX_PER_RUN
    assert len(sent) == workspace.WEBHOOK_MAX_PER_RUN + 1 and "4 more" in sent[-1]


def test_the_test_message_endpoint(client, monkeypatch):
    sent = []
    monkeypatch.setattr(workspace, "post_webhook", lambda url, text: sent.append(text))
    h = setup_webhook(client, monkeypatch)
    assert client.post("/api/workspace/webhook/test", headers=h).status_code == 200 and sent
    client.put("/api/workspace/settings", json={"webhook_url": ""}, headers=h)
    assert client.post("/api/workspace/webhook/test", headers=h).status_code == 400


# ---------------- deleting an account ----------------

def test_deleting_an_account_removes_everything_that_belongs_to_it(client, monkeypatch):
    h, out = setup_digest(client, monkeypatch)
    put_items(client, breach_item("Acme"))
    client.post("/api/workspace/digest/send", headers=h)
    key = client.post("/api/workspace/keys", json={"label": "k"}, headers=h).json()["key"]
    assert client.delete("/api/account", headers=h).status_code == 200
    con = client.module.con()
    for table in ("users", "workspaces", "ws_watch", "sessions", "api_keys", "ws_notified", "login_tokens"):
        assert con.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"] == 0, table
    assert client.get("/api/me", headers=h).status_code == 401
    assert client.get("/api/workspace/alerts", headers={"X-API-Key": key}).status_code == 401


def test_deleting_one_account_leaves_another_alone(client):
    a, b = sign_in(client, "a@example.com"), sign_in(client, "b@example.com")
    client.post("/api/workspace/watch", json={"kind": "product", "value": "screenconnect"}, headers=b)
    client.delete("/api/account", headers=a)
    assert client.get("/api/workspace", headers=b).json()["entries"] == [{"kind": "product", "value": "screenconnect"}]


# ---------------- concurrency ----------------

def test_simultaneous_sign_ins_and_writes_do_not_fail(client):
    results = []

    def go(i):
        h = sign_in(client, f"user{i}@example.com")
        results.append(client.post("/api/workspace/watch", json={"kind": "product", "value": f"thing{i}x"}, headers=h).status_code)
    threads = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    [t.join(timeout=60) for t in threads]
    assert len(results) == 6 and set(results) == {200}
    assert len(accounts.all_workspaces(client.module.con())) == 6


# ---------------- the mailer ----------------

def test_mailer_refuses_when_unconfigured_or_for_bad_addresses(monkeypatch):
    for k in ("BREVO_API_KEY", "SMTP_HOST"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(mailer.MailError):
        mailer.send("a@example.com", "s", "b")
    monkeypatch.setenv("BREVO_API_KEY", "k")
    for bad in ("", "nope", "a b@example.com", "a@example.com,b@example.com", "a@example.com>"):
        with pytest.raises(mailer.MailError):
            mailer.send(bad, "s", "b")


def test_brevo_request_is_clean_and_failures_do_not_leak_the_key(monkeypatch):
    import requests
    monkeypatch.setenv("BREVO_API_KEY", "super-secret-key")
    monkeypatch.setenv("MAIL_FROM", "noreply@darklens.example")
    sent = {}

    class R:
        status_code = 201
    monkeypatch.setattr(requests, "post", lambda url, **k: sent.update(url=url, **k) or R())
    mailer.send("a@example.com", "Hello\r\nBcc: x@y.com", "body")
    assert sent["url"].startswith("https://api.brevo.com/") and "\n" not in sent["json"]["subject"] and sent["json"]["to"] == [{"email": "a@example.com"}]
    assert sent["json"]["sender"]["email"] == "noreply@darklens.example"
    R.status_code = 401
    with pytest.raises(mailer.MailError) as e:
        mailer.send("a@example.com", "s", "b")
    assert "super-secret-key" not in str(e.value)
    monkeypatch.setattr(requests, "post", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("super-secret-key leaked here")))
    with pytest.raises(mailer.MailError) as e2:
        mailer.send("a@example.com", "s", "b")
    assert "super-secret-key" not in str(e2.value)


def test_smtp_path_builds_one_message(monkeypatch):
    for k in ("BREVO_API_KEY",):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SMTP_HOST", "smtp.example")
    monkeypatch.setenv("SMTP_USER", "me@example.com")
    got = {}

    class FakeSMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): got["tls"] = True
        def login(self, *a): got["login"] = a
        def send_message(self, msg): got["msg"] = msg
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    mailer.send("to@example.com", "Subject\nBcc: evil@x.com", "text")
    assert got["tls"] and got["msg"]["To"] == "to@example.com" and got["msg"]["Bcc"] is None and "\n" not in got["msg"]["Subject"]


def test_daily_email_budget_protects_the_provider_quota(monkeypatch):
    import time

    from darklens import mailer

    monkeypatch.setenv("BREVO_API_KEY", "k")
    monkeypatch.setenv("MAIL_DAILY_LIMIT", "3")
    mailer._sent[:] = []

    class R:
        status_code = 201

    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: R())
    for _ in range(3):
        mailer.send("a@example.com", "s", "b")
    with pytest.raises(mailer.MailError, match="today"):
        mailer.send("a@example.com", "s", "b")
    mailer._sent[:] = [time.time() - 90000] * 3  # yesterday's sends no longer count
    mailer.send("a@example.com", "s", "b")
    monkeypatch.setenv("MAIL_DAILY_LIMIT", "0")  # 0 = no cap
    mailer._sent[:] = [time.time()] * 999
    mailer.send("a@example.com", "s", "b")
    mailer._sent[:] = []
