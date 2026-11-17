"""Botnet command-and-control servers from the abuse.ch Feodo Tracker blocklist.

No key for this download. Each entry is a server that was used to control a botnet (Emotet, Dridex, QakBot and so on).
Like other lone indicators it is capped at Low unless it mentions something on your watchlist; one that is currently
online is given a higher confidence. Credit: "Source: abuse.ch Feodo Tracker".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import Item
from .base import cached_get, text

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
ATTRIBUTION = "Source: abuse.ch Feodo Tracker (feodotracker.abuse.ch)"


def parse(data, days: int = 365, limit: int = 100) -> list[Item]:
    if not isinstance(data, list):
        raise RuntimeError("Unexpected answer from Feodo Tracker.")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = [r for r in data if isinstance(r, dict) and text(r.get("ip_address"), 64)
            and (text(r.get("last_online")) or text(r.get("first_seen")))[:10] >= cutoff]
    rows.sort(key=lambda r: text(r.get("last_online")) or text(r.get("first_seen")), reverse=True)
    out = []
    for r in rows[:max(limit, 0)]:
        online = text(r.get("status"), 20).lower() == "online"
        malware = text(r.get("malware"), 60) or "botnet"
        port = r.get("port")
        ip = text(r.get("ip_address"), 64)
        where = f"{ip}:{port}" if isinstance(port, int) and not isinstance(port, bool) else ip
        out.append(Item(source="feodo", kind="ioc", title=f"{malware} botnet command server",
                        text=f"Botnet command server ({malware}): {where} status {text(r.get('status'), 20) or 'unknown'} "
                             f"country {text(r.get('country'), 8)}",
                        seen_at=(text(r.get("last_online")) or text(r.get("first_seen")))[:10], actor=malware,
                        meta={"confidence": 90 if online else 60, "attribution": ATTRIBUTION, "status": text(r.get("status"), 20)}))
    return out


def fetch(offline: bool = True, days: int = 365, limit: int = 100) -> list[Item]:
    if offline:
        return []
    return parse(cached_get(URL, ttl=1800), days, limit)
