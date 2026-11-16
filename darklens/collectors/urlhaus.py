"""abuse.ch URLhaus collector: web addresses that are currently or recently serving malware.

API: GET https://urlhaus-api.abuse.ch/v1/urls/recent/limit/N/ with header `Auth-Key` (the same free key as ThreatFox).
The answer is {"query_status": "ok", "urls": [...]}; with nothing to report, `query_status` is "no_results" and `urls`
is missing. Only the list of addresses is read. Malware samples are never downloaded.

Like ThreatFox indicators, these are lone indicators, so they are capped at Low unless they mention your watchlist.
The online/offline status is kept out of the stored text, so an address that flips status keeps the same item id
instead of creating a duplicate each time.
"""
from __future__ import annotations

import os

from ..models import Item
from .base import USER_AGENT

URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
_CONFIDENCE = {"online": 80, "offline": 40}  # anything else (unknown) is 50


class MissingKey(RuntimeError):
    """Live mode needs a (free) abuse.ch Auth-Key."""


def _to_item(r: dict) -> Item:
    tags = [t for t in (r.get("tags") or []) if isinstance(t, str)]
    family = tags[0] if tags else "malware"
    host = r.get("host") or ""
    return Item(source="urlhaus", kind="ioc", title=f"URLhaus {family} download link",
                text=f"Malware download link ({host}): {r['url']} tags: {', '.join(tags) or 'none'}",
                url=r.get("urlhaus_reference") or "", seen_at=(r.get("date_added") or "")[:10],
                actor=family, meta={"confidence": _CONFIDENCE.get(r.get("url_status") or "", 50),
                                    "status": r.get("url_status"), "threat": r.get("threat")})


def parse(body: dict) -> list[Item]:
    status = body.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise RuntimeError(f"URLhaus answered '{status}'.")
    urls = body.get("urls")
    if not isinstance(urls, list):
        return []
    return [_to_item(x) for x in urls if isinstance(x, dict) and x.get("url")]


def fetch(offline: bool = True, limit: int = 100) -> list[Item]:
    if offline:
        return []  # no demo samples: the demo set is about posts
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        raise MissingKey("Set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/) for live URLhaus.")
    import requests

    r = requests.get(URL.format(limit=min(max(limit, 1), 1000)), headers={"Auth-Key": key, "User-Agent": USER_AGENT}, timeout=30)
    r.raise_for_status()
    return parse(r.json())
