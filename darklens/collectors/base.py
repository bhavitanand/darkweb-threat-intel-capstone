from __future__ import annotations

import json
import time
from pathlib import Path

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
CACHE = Path(__file__).resolve().parents[2] / ".cache"
USER_AGENT = "DarkLens-research/0.1 (academic capstone; non-commercial)"


def load_sample(name: str):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def cached_get(url: str, ttl: int = 1800, headers: dict | None = None, timeout: int = 20):
    """GET with an on-disk cache. 30 minutes by default to respect Ransomware.live fair-use terms."""
    import hashlib

    import requests

    CACHE.mkdir(exist_ok=True)
    f = CACHE / (hashlib.sha1(url.encode()).hexdigest() + ".json")
    if f.exists() and time.time() - f.stat().st_mtime < ttl:
        return json.loads(f.read_text())
    h = {"User-Agent": USER_AGENT, **(headers or {})}
    r = requests.get(url, headers=h, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    f.write_text(json.dumps(data))
    return data
