"""Live phishing pages from the OpenPhish community feed (https://openphish.com).

No key. One address per line. A lone phishing address is news about the internet, not about you, so each is an
indicator (capped at Low) unless it mentions something on your watchlist. The feed is for non-commercial use; it is
credited as "Source: OpenPhish". Only the address list is read: nothing is visited or downloaded.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Item, now_iso
from .base import cached_get_text

URL = "https://openphish.com/feed.txt"
ATTRIBUTION = "Source: OpenPhish community feed (openphish.com), non-commercial use"
_URL = re.compile(r"^https?://[^\s<>\"']{4,500}$", re.I)


def parse(body: str, limit: int = 150) -> list[Item]:
    seen, out = set(), []
    for line in (body or "").splitlines():
        if len(out) >= max(limit, 0):
            break
        u = line.strip()
        if not _URL.match(u) or u in seen:
            continue
        seen.add(u)
        try:
            host = (urlsplit(u).hostname or "")[:120]
        except ValueError:  # a malformed address (for example a bad IPv6 bracket) is skipped, not fatal
            continue
        out.append(Item(source="openphish", kind="ioc", title="OpenPhish phishing page",
                        text=f"Phishing page (OpenPhish) on {host}: {u}", url="", seen_at=now_iso()[:10], actor="phishing",
                        meta={"confidence": 85, "attribution": ATTRIBUTION}))
    return out


def fetch(offline: bool = True, limit: int = 150) -> list[Item]:
    if offline:
        return []
    return parse(cached_get_text(URL), limit)
