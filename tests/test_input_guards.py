"""NUL characters and database refusals must never become a bare 500."""
import pytest
from fastapi.testclient import TestClient
from helpers import load_app


@pytest.fixture
def client(monkeypatch):
    with TestClient(load_app(monkeypatch).app, raise_server_exceptions=False) as c:
        yield c


@pytest.mark.parametrize("path", ["/api/alerts?q=%00", "/api/alerts?q=a%00b", "/api/alerts?q=%00%F0%9F%92%80", "/api/alerts?category=%00",
                                  "/api/enrich?kind=domain&value=a%00.com", "/api/alerts/%00"])
def test_nul_in_address_is_a_400(client, path):
    r = client.get(path)
    assert r.status_code == 400 and "not allowed" in r.json()["detail"]


def test_ordinary_requests_still_work(client):
    assert client.get("/api/alerts?q=100%25").status_code == 200  # an escaped percent sign is not a NUL
    assert client.get("/api/alerts?q=%F0%9F%92%80").status_code == 200


def test_database_data_errors_become_400_other_errors_stay_500(client):
    import psycopg

    app = client.app

    @app.get("/_t/data")
    def _data():
        raise psycopg.errors.DataError("A string literal cannot contain NUL (0x00) characters.")

    @app.get("/_t/boom")
    def _boom():
        raise RuntimeError("real bug")

    assert client.get("/_t/data").status_code == 400
    assert client.get("/_t/boom").status_code == 500
