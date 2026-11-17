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
from .base import USER_AGENT, text

URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
_CONFIDENCE = {"online": 80, "offline": 40}  # anything else (unknown) is 50


class MissingKey(RuntimeError):
    """Live mode needs a (free) abuse.ch Auth-Key."""


def _to_item(r: dict) -> Item:
    raw_tags = r.get("tags")
    tags = [t[:60] for t in (raw_tags if isinstance(raw_tags, list) else []) if isinstance(t, str)][:20]
    family = tags[0] if tags else "malware"
    status = text(r.get("url_status"), 30)
    return Item(source="urlhaus", kind="ioc", title=f"URLhaus {family} download link",
                text=f"Malware download link ({text(r.get('host'), 255)}): {text(r.get('url'))} tags: {', '.join(tags) or 'none'}",
                url=text(r.get("urlhaus_reference")), seen_at=text(r.get("date_added"))[:10],
                actor=family, meta={"confidence": _CONFIDENCE.get(status, 50),
                                    "status": status, "threat": text(r.get("threat"), 60)})


def parse(body: dict) -> list[Item]:
    if not isinstance(body, dict):
        raise RuntimeError("URLhaus answered with something that is not a JSON object.")
    status = body.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise RuntimeError(f"URLhaus answered '{status}'.")
    urls = body.get("urls")
    if not isinstance(urls, list):
        return []
    return [_to_item(x) for x in urls if isinstance(x, dict) and text(x.get("url"))]


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
