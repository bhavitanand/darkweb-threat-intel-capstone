"""Live security news from public RSS feeds: headline, a short summary and a link back, nothing more.

No key. This casts a wide net (breaches, ransomware incidents, exploited flaws and attacks are reported here first), and
every item goes through the same classifier and rules as everything else. A headline and a link are how news is
normally shared, but the sites own their text, so each item is flagged `no_redistribute`: it is shown with a link to
the source, never returned in full by the API or put in an export (the same treatment as Ransomware.live).

Feeds are untrusted input: size-capped, and anything declaring a DTD or entity is refused (see labelling/sources.py).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime

from ..labelling.sources import FEEDS, USER_AGENT, parse_feed
from ..models import Item, now_iso

PER_FEED = 12


def _day(raw: str) -> str:
    """A feed date (RFC 822 or ISO 8601) as YYYY-MM-DD, or "" when it is missing or unreadable."""
    if not raw:
        return ""
    try:
        return parsedate_to_datetime(raw).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        pass
    return raw[:10] if len(raw) >= 10 and raw[4] == "-" and raw[7] == "-" else ""


def to_items(entries: list[dict], source: str, per_feed: int = PER_FEED) -> list[Item]:
    out = []
    for e in entries[:max(per_feed, 0)]:
        link = e.get("link") or ""
        out.append(Item(source=source, kind="post", title=e["title"][:200], text=e["text"][:600],
                        url=link if link.startswith(("http://", "https://")) else "", seen_at=_day(e.get("date", "")) or now_iso()[:10],  # undated items get today, so they can expire
                        meta={"no_redistribute": True, "attribution": f"Source: {source} (headline and link)", "news": True}))
    return out


def _one(feed) -> list[Item]:
    import requests

    name, url, _kind = feed
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
    r.raise_for_status()
    return to_items(parse_feed(r.content[:2_000_000], name, "security"), name)


def _safe(feed):
    try:
        return _one(feed)
    except Exception:  # noqa: BLE001  (one feed being down must not lose the others)
        return None


def fetch(offline: bool = True) -> list[Item]:
    if offline:
        return []
    feeds = [f for f in FEEDS if f[2] == "security"]
    items: list[Item] = []
    failed = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        for res in pool.map(_safe, feeds):
            if res is None:
                failed += 1
            else:
                items += res
    if not items and failed:
        raise RuntimeError(f"All {failed} news feeds failed.")
    return items
