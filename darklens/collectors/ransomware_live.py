"""Ransomware.live collector (public ransomware victim claims).

Source: https://www.ransomware.live   Terms: https://www.ransomware.live/t&c  (read them before running live)

What the terms mean for this code:
* Use the PRO API (free key from https://my.ransomware.live, sent as the X-API-KEY header). The legacy API is
  "personal use only", so live mode needs RANSOMWARE_LIVE_API_KEY and is skipped without one.
* Non-commercial use with attribution ("Source: Ransomware.live", linked) on every page that shows the data.
* Cache 30 minutes. Do not re-serve or publish the raw data. Items from this source are therefore flagged
  `no_redistribute` and the API withholds their free text and leaves them out of CSV and STIX exports.
"""
from __future__ import annotations

import os

from ..models import Item
from .base import cached_get, load_sample, text

BASE = os.environ.get("RANSOMWARE_LIVE_BASE", "https://api-pro.ransomware.live").rstrip("/")
KEY_ENV = "RANSOMWARE_LIVE_API_KEY"
ATTRIBUTION = "Source: Ransomware.live"
SITE = "https://www.ransomware.live"


class MissingKey(RuntimeError):
    """Live mode needs a (free) Ransomware.live API key."""


def _to_item(v: dict) -> Item:
    org = text(v.get("victim")) or text(v.get("post_title"))
    group = text(v.get("group")) or text(v.get("group_name"))
    sector = text(v.get("activity"))
    site = text(v.get("website")) or text(v.get("domain"))
    desc = text(v.get("description"))  # the legacy API had one; the PRO API documents none
    body = f"{org} was claimed by {group}."
    if sector and sector.lower() != "not found":
        body += f" Sector: {sector}."
    if site:
        body += f" Website: {site}."
    if desc:
        body += f" {desc}"
    return Item(
        source="ransomware.live", kind="leak_claim", title=f"{group}: {org}", text=body.strip(),
        url=text(v.get("permalink")) or text(v.get("url")),
        seen_at=(text(v.get("attackdate")) or text(v.get("discovered")))[:10],
        actor=group, org=org, country=text(v.get("country"), 80),
        meta={"attribution": ATTRIBUTION, "no_redistribute": True},
    )


def fetch(offline: bool = True, limit: int = 100) -> list[Item]:
    if offline:
        data = load_sample("ransomware_live.json")
        items = [_to_item(v) for v in data[:limit]]
        for it in items:
            it.meta.pop("no_redistribute", None)  # the demo samples are fictional, so they can be shared
        return items
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        raise MissingKey(f"Set {KEY_ENV} (free key from https://my.ransomware.live) to collect live claims.")
    data = cached_get(f"{BASE}/victims/recent", headers={"X-API-KEY": key})
    if isinstance(data, dict):  # tolerate a wrapped response
        data = data.get("victims") or data.get("data") or []
    if not isinstance(data, list):
        raise RuntimeError("Unexpected answer from Ransomware.live.")
    return [_to_item(v) for v in data[:max(limit, 0)] if isinstance(v, dict)]
