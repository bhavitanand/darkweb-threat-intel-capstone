"""abuse.ch ThreatFox collector. Requires a free Auth-Key from https://auth.abuse.ch/ for live mode."""
from __future__ import annotations

import os

from ..models import Item
from .base import USER_AGENT, load_sample

URL = "https://threatfox-api.abuse.ch/api/v1/"


def _to_item(r: dict) -> Item:
    text = (f"{r.get('malware', 'unknown malware')} indicator ({r.get('threat_type', '')}): {r['ioc']} "
            f"confidence {r.get('confidence_level', '?')}")
    return Item(source="threatfox", kind="ioc", title=f"{r.get('malware', '')} {r.get('ioc_type', '')}",
                text=text, seen_at=(r.get("first_seen") or "")[:10], actor=r.get("malware", ""),
                meta={"ioc_type": r.get("ioc_type"), "confidence": r.get("confidence_level")})


def fetch(offline: bool = True, days: int = 1) -> list[Item]:
    if offline:
        return [_to_item(r) for r in load_sample("threatfox.json")]
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        raise RuntimeError("Set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/) for live ThreatFox.")
    import requests

    r = requests.post(URL, json={"query": "get_iocs", "days": min(max(days, 1), 7)},
                      headers={"Auth-Key": key, "User-Agent": USER_AGENT}, timeout=30)
    r.raise_for_status()
    return [_to_item(x) for x in (r.json().get("data") or [])]
