"""The rate limiter, driven by a fake clock so no test ever sleeps."""
import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from helpers import load_app

from darklens.api.ratelimit import RateLimitMiddleware


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def build(read=3, write=2, trust_proxy=False, clock=None):
    app = FastAPI()

    @app.get("/api/x")
    def x():
        return {"ok": 1}

    @app.post("/api/w")
    def w():
        return {"ok": 1}

    @app.get("/api/health")
    def health():
        return {"ok": 1}

    @app.get("/other")
    def other():
        return {"ok": 1}

    app.add_middleware(RateLimitMiddleware, read_per_min=read, write_per_min=write, trust_proxy=trust_proxy,
                       clock=clock or Clock())
    return app


def test_reads_are_limited_then_recover_after_a_minute():
    clock = Clock()
    c = TestClient(build(clock=clock))
    assert [c.get("/api/x").status_code for _ in range(3)] == [200, 200, 200]
    blocked = c.get("/api/x")
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) >= 1
    assert "Too many requests" in blocked.json()["detail"]
    clock.t += 61
    assert c.get("/api/x").status_code == 200


def test_reads_and_writes_have_separate_budgets():
    c = TestClient(build())
    assert [c.post("/api/w").status_code for _ in range(3)] == [200, 200, 429]
    assert c.get("/api/x").status_code == 200


def test_health_other_paths_and_preflights_are_never_limited():
    c = TestClient(build(read=1, write=1))
    for _ in range(10):
        assert c.get("/api/health").status_code == 200
        assert c.get("/other").status_code == 200
        assert c.options("/api/x").status_code != 429


def test_clients_are_counted_separately_behind_a_proxy():
    c = TestClient(build(read=1, trust_proxy=True))
    assert c.get("/api/x", headers={"X-Forwarded-For": "1.1.1.1, 10.0.0.1"}).status_code == 200
    assert c.get("/api/x", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
    assert c.get("/api/x", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200


def test_forwarded_header_is_ignored_unless_proxy_is_trusted():
    c = TestClient(build(read=1, trust_proxy=False))
    assert c.get("/api/x", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert c.get("/api/x", headers={"X-Forwarded-For": "9.9.9.9"}).status_code == 429  # a forged header buys nothing


def test_zero_turns_a_limit_off():
    c = TestClient(build(read=0, write=0))
    assert all(c.get("/api/x").status_code == 200 for _ in range(50))


def test_memory_is_bounded(monkeypatch):
    import darklens.api.ratelimit as rl
    monkeypatch.setattr(rl, "MAX_CLIENTS", 50)
    mw = RateLimitMiddleware(app=None, read_per_min=5)
    for i in range(200):
        mw._allow((f"10.0.{i}.1", "read"), 5)
    assert len(mw.hits) <= 60


def test_real_app_limits_and_429_still_carries_cors(monkeypatch):
    module = load_app(monkeypatch, RATE_LIMIT_PER_MIN=3, ALLOWED_ORIGINS="https://app.example")
    with TestClient(module.app) as c:
        h = {"Origin": "https://app.example"}
        codes = [c.get("/api/stats", headers=h).status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
        limited = c.get("/api/stats", headers=h)
        assert limited.headers["access-control-allow-origin"] == "https://app.example"
        assert c.get("/api/health").status_code == 200  # monitors are never throttled
