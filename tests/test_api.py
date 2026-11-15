"""API behaviour the new frontend and the uptime monitor depend on: CORS and the HEAD-friendly health route."""
import importlib
import os
import tempfile

import pytest
from fastapi.testclient import TestClient


def load_app(monkeypatch, origins: str | None):
    monkeypatch.setenv("DARKLENS_DB", os.path.join(tempfile.mkdtemp(), "api.db"))
    if origins is None:
        monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("ALLOWED_ORIGINS", origins)
    from darklens.api import app as module
    module = importlib.reload(module)
    return module.app


def test_health_answers_get_and_head(monkeypatch):
    with TestClient(load_app(monkeypatch, None)) as client:
        assert client.get("/api/health").json()["ok"] is True
        head = client.head("/api/health")
        assert head.status_code == 200


def test_cors_is_off_by_default(monkeypatch):
    with TestClient(load_app(monkeypatch, None)) as client:
        reply = client.get("/api/health", headers={"Origin": "https://darklens.vercel.app"})
        assert "access-control-allow-origin" not in reply.headers


def test_cors_allows_only_listed_origins(monkeypatch):
    with TestClient(load_app(monkeypatch, "https://darklens.vercel.app/, http://localhost:5173")) as client:
        ok = client.get("/api/health", headers={"Origin": "https://darklens.vercel.app"})
        assert ok.headers["access-control-allow-origin"] == "https://darklens.vercel.app"
        other = client.get("/api/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in other.headers


def test_cors_preflight_for_post(monkeypatch):
    with TestClient(load_app(monkeypatch, "https://darklens.vercel.app")) as client:
        reply = client.options("/api/analyse", headers={
            "Origin": "https://darklens.vercel.app", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type"})
        assert reply.status_code == 200
        assert reply.headers["access-control-allow-origin"] == "https://darklens.vercel.app"


@pytest.mark.parametrize("path", ["/api/stats", "/api/alerts", "/api/graph", "/api/watchlist", "/api/eval"])
def test_read_endpoints_work_on_demo_data(monkeypatch, path):
    with TestClient(load_app(monkeypatch, None)) as client:
        assert client.get(path).status_code == 200
