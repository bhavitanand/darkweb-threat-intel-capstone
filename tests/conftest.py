import pytest


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch, tmp_path):
    """Tests never touch a real database, send alerts, or throttle themselves, whatever the shell has set."""
    for name in ("DATABASE_URL", "ALERT_WEBHOOK_URL", "SMTP_HOST", "ALERT_EMAIL_TO", "AUTO_INGEST_MINUTES",
                 "INGEST_TOKEN", "ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DARKLENS_DB", str(tmp_path / "t.db"))
    from darklens.collectors import base
    monkeypatch.setattr(base, "CACHE", tmp_path / "cache")  # never read or write the real on-disk feed cache
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "0")  # 0 = off; rate-limit tests turn it on explicitly


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """A test must never reach the real internet: it would be slow, flaky, and could hit a source's rate limit.
    Tests that need a response patch the collector (or requests.get/post) themselves."""
    import requests

    def blocked(*args, **kwargs):
        raise AssertionError("a test tried to use the network")

    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
