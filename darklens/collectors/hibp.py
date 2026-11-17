"""Recent data breaches from Have I Been Pwned (https://haveibeenpwned.com/api/v3/breaches).

No key and no login: it is a public list. Each entry is a real, verified breach with a prose write-up. The data is
licensed CC BY 4.0, so it may be shown and exported with attribution ("Source: Have I Been Pwned"). Only breaches added
in the last `days` days (inside the default 90-day retention, or they would be pruned and re-added in a loop) are collected, newest first; older ones are used for training (darklens/nlp/realdata.py), not
shown as new alerts. Spam lists and fabricated entries are skipped.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import Item
from .base import cached_get, text

URL = "https://haveibeenpwned.com/api/v3/breaches"
ATTRIBUTION = "Source: Have I Been Pwned (haveibeenpwned.com), CC BY 4.0"


def _to_item(b: dict) -> Item:
    from ..nlp.realdata import clean_html

    name = text(b.get("Title"), 120) or text(b.get("Name"), 120)
    raw_classes = b.get("DataClasses")
    classes = [c for c in (raw_classes if isinstance(raw_classes, list) else []) if isinstance(c, str)][:12]
    body = clean_html(text(b.get("Description"), 1500))
    if classes:
        body += f" Data exposed: {', '.join(classes)}."
    count = b.get("PwnCount")
    return Item(source="haveibeenpwned", kind="breach_report", title=f"{name}: data breach", text=body,
                url=f"https://haveibeenpwned.com/PwnedWebsites#{text(b.get('Name'), 80)}",
                seen_at=text(b.get("AddedDate"))[:10], actor="", org=name, country="",
                meta={"attribution": ATTRIBUTION, "accounts": count if isinstance(count, int) else None,
                      "verified": bool(b.get("IsVerified"))})


def fetch(offline: bool = True, days: int = 60, limit: int = 60) -> list[Item]:
    if offline:
        return []  # no demo samples; it needs no key, so live mode just works
    data = cached_get(URL, ttl=3600)
    if not isinstance(data, list):
        raise RuntimeError("Unexpected answer from Have I Been Pwned.")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = [b for b in data if isinstance(b, dict) and not b.get("IsSpamList") and not b.get("IsFabricated")
            and text(b.get("AddedDate"))[:10] >= cutoff and len(text(b.get("Description"))) >= 40]
    rows.sort(key=lambda b: text(b.get("AddedDate")), reverse=True)
    return [_to_item(b) for b in rows[:max(limit, 0)]]
