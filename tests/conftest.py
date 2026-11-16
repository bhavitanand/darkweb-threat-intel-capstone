import pytest


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch, tmp_path):
    """Tests never touch a real database, send alerts, or throttle themselves, whatever the shell has set."""
    for name in ("DATABASE_URL", "ALERT_WEBHOOK_URL", "SMTP_HOST", "ALERT_EMAIL_TO", "AUTO_INGEST_MINUTES",
                 "INGEST_TOKEN", "ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DARKLENS_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "0")  # 0 = off; rate-limit tests turn it on explicitly
