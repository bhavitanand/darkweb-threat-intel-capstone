import importlib


def load_app(monkeypatch, **env):
    """Import a fresh copy of the API with the given environment (DARKLENS_DB is already isolated by conftest)."""
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    from darklens.api import app as module
    return importlib.reload(module)
