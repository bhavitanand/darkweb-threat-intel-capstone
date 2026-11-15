"""Forum / channel posts. Offline: synthetic demo posts. Live: snippets from the allowlisted Tor crawler."""
from __future__ import annotations

from ..models import Item
from .base import load_sample


def fetch(offline: bool = True) -> list[Item]:
    if not offline:
        return []  # live posts come from darklens.crawler.tor, see README
    out = []
    for p in load_sample("forum_posts.json"):
        out.append(Item(source=p["source"], kind="post", title=p["title"], text=p["text"],
                        actor=p.get("author", ""), seen_at="2026-11-15"))
    return out
