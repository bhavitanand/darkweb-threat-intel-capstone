"""Collecting on a schedule and telling people: error isolation, status, demo handling, de-duplication."""
import pytest

from darklens import ingest, notify, pipeline
from darklens.models import Item
from darklens.store import db


@pytest.fixture
def con(tmp_path):
    c = db.connect(tmp_path / "n.db")
    yield c
    c.close()


def _fake_sources(monkeypatch, rw=None, tf=None, fo=None):
    def boom(offline=True):
        raise ConnectionError("feed is down")

    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "test-key")  # live Ransomware.live collection requires a key
    monkeypatch.setattr(ingest.ransomware_live, "fetch", rw or (lambda offline=True: []))
    monkeypatch.setattr(ingest.threatfox, "fetch", tf or (lambda offline=True: []))
    monkeypatch.setattr(ingest.forums, "fetch", fo or (lambda offline=True: []))
    return boom


# ---- ingest ----

def test_one_broken_source_does_not_stop_the_others(monkeypatch, con):
    boom = _fake_sources(monkeypatch, rw=lambda offline=True: [Item(source="ransomware.live", kind="leak_claim", title="G: Org",
                                                             text="Org was claimed by G. Data will be published in 3 days.")])
    monkeypatch.setattr(ingest.threatfox, "fetch", boom)
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "set")
    st = ingest.run_ingest(live=True, con=con)
    by = {s["source"]: s for s in st["sources"]}
    assert by["ransomware.live"]["status"] == "ok" and by["ransomware.live"]["items"] == 1
    assert by["threatfox"]["status"] == "error" and "ConnectionError" in by["threatfox"]["note"]
    assert st["ok"] is False and st["items"] == 1 and st["mode"] == "live"


def test_missing_key_is_skipped_not_an_error(monkeypatch, con):
    _fake_sources(monkeypatch)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    by = {s["source"]: s for s in ingest.run_ingest(live=True, con=con)["sources"]}
    assert by["threatfox"]["status"] == "skipped" and "key" in by["threatfox"]["note"].lower()
    assert by["forums"]["status"] == "skipped"


def test_status_is_persisted_and_demo_items_are_marked(monkeypatch, con):
    assert ingest.status(con)["last"] is None
    ingest.run_ingest(live=False, con=con)
    st = ingest.status(con)
    assert st["last"]["mode"] == "demo" and st["live_ready"] is False
    import json
    metas = [json.loads(r["meta"]) for r in con.execute("SELECT meta FROM items")]
    assert metas and all(m.get("demo") for m in metas)


def test_live_items_are_not_marked_demo(monkeypatch, con):
    _fake_sources(monkeypatch, rw=lambda offline=True: [Item(source="ransomware.live", kind="leak_claim", title="t", text="x ransom")])
    ingest.run_ingest(live=True, con=con)
    import json
    assert not json.loads(con.execute("SELECT meta FROM items").fetchone()["meta"]).get("demo")


@pytest.mark.parametrize("raw,expected", [("", 0), ("0", 0), ("-5", 0), ("abc", 0), ("10", 30), ("60", 60)])
def test_interval_is_clamped_to_the_fair_use_minimum(monkeypatch, raw, expected):
    monkeypatch.setenv("AUTO_INGEST_MINUTES", raw)
    assert ingest.interval_minutes() == expected


def test_scheduler_is_off_unless_configured(monkeypatch):
    import threading
    monkeypatch.delenv("AUTO_INGEST_MINUTES", raising=False)
    assert ingest.start_scheduler(threading.Lock()) is None


def test_live_run_prunes_old_real_data(monkeypatch, con):
    old = Item(source="x", kind="post", title="ancient", text="ransom will be published", seen_at="2019-01-01")
    pipeline.run(items=[old], con=con)
    _fake_sources(monkeypatch)
    monkeypatch.setenv("RETENTION_DAYS", "30")
    assert ingest.run_ingest(live=True, con=con)["pruned"] == 1
    monkeypatch.setenv("RETENTION_DAYS", "0")
    assert ingest.run_ingest(live=True, con=con)["pruned"] == 0


# ---- notify ----

class Sink:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def __call__(self, url, text):
        if self.fail:
            raise ConnectionError("down")
        self.sent.append(text)


def _store_watch_hit(con, title="Acme leak"):
    db.watch_add(con, "domain", "acme.example")
    it = Item(source="ransomware.live", kind="post", title=title,
              text="a@acme.example:Passw0rd1 b@acme.example:Passw0rd2 c@acme.example:Passw0rd3 database dump")
    pipeline.run(items=[it], con=con)
    return it


def test_nothing_is_sent_without_a_channel(con):
    _store_watch_hit(con)
    assert notify.channels() == [] and notify.dispatch(con) == 0


def test_watchlist_hit_is_sent_once_with_a_link_and_no_password(monkeypatch, con):
    sink = Sink()
    monkeypatch.setattr(notify, "send_webhook", sink)
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example/x")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://app.example/")
    it = _store_watch_hit(con)
    assert notify.dispatch(con) == 1
    assert notify.dispatch(con) == 0  # already sent
    msg = sink.sent[0]
    assert "Acme leak" in msg and f"https://app.example/#/alerts/{it.id}" in msg and "Passw0rd" not in msg


def test_demo_data_never_notifies_unless_asked(monkeypatch, con):
    sink = Sink()
    monkeypatch.setattr(notify, "send_webhook", sink)
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example/x")
    db.watch_add(con, "domain", "granite-bank.example")
    ingest.run_ingest(live=False, con=con)
    assert sink.sent == []
    monkeypatch.setenv("NOTIFY_DEMO", "1")
    assert notify.dispatch(con) >= 1


def test_levels_control_what_counts(monkeypatch, con):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example/x")
    pipeline.run(items=[Item(source="x", kind="post", title="Zero day", text="Selling 0day RCE for Exchange VPN, CVE-2026-5555 working, 2 XMR initial access")], con=con)
    assert notify.pending(con, "webhook") == []  # not about the watchlist
    monkeypatch.setenv("NOTIFY_MIN", "high")
    assert [a["title"] for a in notify.pending(con, "webhook")] == ["Zero day"]
    monkeypatch.setenv("NOTIFY_MIN", "bogus")  # unknown value falls back to watchlist-only
    assert notify.pending(con, "webhook") == []


def test_a_failing_channel_is_retried_next_run(monkeypatch, con):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example/x")
    _store_watch_hit(con)
    monkeypatch.setattr(notify, "send_webhook", Sink(fail=True))
    assert notify.dispatch(con) == 0
    sink = Sink()
    monkeypatch.setattr(notify, "send_webhook", sink)
    assert notify.dispatch(con) == 1


def test_a_burst_is_capped_and_summarised(monkeypatch, con):
    sink = Sink()
    monkeypatch.setattr(notify, "send_webhook", sink)
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example/x")
    db.watch_add(con, "domain", "acme.example")
    items = [Item(source="x", kind="post", title=f"Leak {i}",
                  text=f"a{i}@acme.example:Passw0rd{i} b{i}@acme.example:Passw0rd{i}x c{i}@acme.example:Passw0rd{i}y dump")
             for i in range(notify.MAX_PER_RUN + 4)]
    pipeline.run(items=items, con=con)
    assert notify.dispatch(con) == notify.MAX_PER_RUN
    assert len(sink.sent) == notify.MAX_PER_RUN + 1 and "4 more alerts" in sink.sent[-1]
    assert notify.dispatch(con) == 0  # the summarised ones are not re-sent


def test_email_channel_builds_a_message(monkeypatch, con):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=0):
            sent["host"], sent["port"] = host, port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, u, p):
            sent["login"] = u

        def send_message(self, m):
            sent["subject"], sent["to"] = m["Subject"], m["To"]

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    for k, v in {"SMTP_HOST": "smtp.example", "SMTP_USER": "u", "SMTP_PASSWORD": "p", "ALERT_EMAIL_TO": "me@example.com"}.items():
        monkeypatch.setenv(k, v)
    assert notify.channels() == ["email"]
    _store_watch_hit(con)
    assert notify.dispatch(con) == 1
    assert sent["host"] == "smtp.example" and sent["port"] == 587 and sent["tls"] and sent["to"] == "me@example.com"
    assert sent["subject"].startswith("DarkLens")
