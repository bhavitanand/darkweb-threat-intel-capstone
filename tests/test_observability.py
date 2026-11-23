import sys

from darklens import observability


def test_off_without_dsn(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    assert observability.init() is False


def test_missing_package_or_bad_dsn_never_raises(monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "not-a-dsn")
    monkeypatch.setitem(sys.modules, "sentry_sdk", None)  # import fails
    assert observability.init() is False


def test_bad_dsn_with_package_is_contained(monkeypatch):
    class Fake:
        @staticmethod
        def init(**kw):
            raise ValueError("bad dsn")

    monkeypatch.setenv("SENTRY_DSN", "x")
    monkeypatch.setitem(sys.modules, "sentry_sdk", Fake)
    assert observability.init() is False
