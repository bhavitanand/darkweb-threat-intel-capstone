from __future__ import annotations

import json
import time
from pathlib import Path

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
CACHE = Path(__file__).resolve().parents[2] / ".cache"
USER_AGENT = "DarkLens-research/0.1 (academic capstone; non-commercial)"


def load_sample(name: str):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def text(v, limit: int = 2000) -> str:
    """A feed field as short, safe text. Live feeds are not ours: a field documented as a string can arrive as a number,
    null, a list or an object, or be enormous. One odd record must never crash the whole collection or fill the database."""
    if isinstance(v, str):
        return v.strip()[:limit]
    if v is None or isinstance(v, (dict, list, tuple, set, bytes, bytearray)):
        return ""
    return str(v)[:limit]


def cached_get(url: str, ttl: int = 1800, headers: dict | None = None, timeout: int = 20):
    """GET with an on-disk cache. 30 minutes by default to respect Ransomware.live fair-use terms."""
    import hashlib

    import requests

    CACHE.mkdir(exist_ok=True)
    f = CACHE / (hashlib.sha1(url.encode()).hexdigest() + ".json")
    if f.exists() and time.time() - f.stat().st_mtime < ttl:
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            pass  # a damaged cache file (for example a write cut short) is not an error: fetch again
    h = {"User-Agent": USER_AGENT, **(headers or {})}
    r = requests.get(url, headers=h, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(f)  # all or nothing, so a crash mid-write cannot leave half a file behind
    return data


def cached_get_text(url: str, ttl: int = 1800, timeout: int = 20, max_bytes: int = 5_000_000) -> str:
    """Like cached_get, for plain-text feeds (one indicator per line). Follows redirects and bounds the size."""
    import hashlib

    import requests

    CACHE.mkdir(exist_ok=True)
    f = CACHE / (hashlib.sha1(url.encode()).hexdigest() + ".txt")
    if f.exists() and time.time() - f.stat().st_mtime < ttl:
        try:
            return f.read_text(encoding="utf-8")
        except (ValueError, OSError):
            pass
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    body = r.content[:max_bytes].decode("utf-8", errors="replace")
    tmp = f.with_suffix(".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(f)
    return body
