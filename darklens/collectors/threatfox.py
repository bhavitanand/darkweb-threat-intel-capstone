"""abuse.ch ThreatFox collector. Requires a free Auth-Key from https://auth.abuse.ch/ for live mode.

API: POST https://threatfox-api.abuse.ch/api/v1/ with header `Auth-Key` and body {"query": "get_iocs", "days": 1-7}.
The answer is {"query_status": "ok", "data": [...]}. When nothing matches, or the key is wrong, `query_status` says so and
`data` is not a list, so the status is checked before the data is read. ThreatFox expires IOCs older than six months.
Use is free under abuse.ch's fair-use principles for non-commercial work.
"""
from __future__ import annotations

import os

from ..models import Item
from .base import USER_AGENT, load_sample

URL = "https://threatfox-api.abuse.ch/api/v1/"


class MissingKey(RuntimeError):
    """Live mode needs a (free) abuse.ch Auth-Key."""


def _to_item(r: dict) -> Item:
    malware = r.get("malware_printable") or r.get("malware") or "unknown malware"
    text = (f"{malware} indicator ({r.get('threat_type', '')}): {r['ioc']} "
            f"confidence {r.get('confidence_level', '?')}")
    return Item(source="threatfox", kind="ioc", title=f"{malware} {r.get('ioc_type', '')}".strip(),
                text=text, seen_at=(r.get("first_seen") or "")[:10], actor=malware,
                meta={"ioc_type": r.get("ioc_type"), "confidence": r.get("confidence_level")})


def parse(body: dict) -> list[Item]:
    """Turn a ThreatFox answer into items, tolerating every shape the API is documented to return."""
    status = body.get("query_status")
    if status == "no_result":
        return []
    if status != "ok":
        raise RuntimeError(f"ThreatFox answered '{status}'.")
    data = body.get("data")
    if not isinstance(data, list):
        return []
    return [_to_item(x) for x in data if isinstance(x, dict) and x.get("ioc")]


def fetch(offline: bool = True, days: int = 1) -> list[Item]:
    if offline:
        return [_to_item(r) for r in load_sample("threatfox.json")]
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        raise MissingKey("Set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/) for live ThreatFox.")
    import requests

    r = requests.post(URL, json={"query": "get_iocs", "days": min(max(days, 1), 7)},
                      headers={"Auth-Key": key, "User-Agent": USER_AGENT}, timeout=30)
    r.raise_for_status()
    return parse(r.json())
