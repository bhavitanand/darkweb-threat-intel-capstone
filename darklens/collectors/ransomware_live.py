"""Ransomware.live collector (victim claims from public leak-site trackers).

Source: https://www.ransomware.live  Non-commercial use only. Attribution required: "Source: Ransomware.live".
Cache for 30 minutes (their fair-use rule). The base URL is configurable because their docs and terms
mention two hosts; confirm the current one before running live.
"""
from __future__ import annotations

import os

from ..models import Item
from .base import cached_get, load_sample

BASE = os.environ.get("RANSOMWARE_LIVE_BASE", "https://api.ransomware.live/v2")
ATTRIBUTION = "Source: Ransomware.live"


def _to_item(v: dict) -> Item:
    org = v.get("victim") or v.get("post_title") or ""
    group = v.get("group") or v.get("group_name") or ""
    desc = v.get("description") or ""
    text = f"{org} was claimed by {group}. {desc}".strip()
    return Item(
        source="ransomware.live", kind="leak_claim", title=f"{group}: {org}", text=text,
        url=v.get("url") or v.get("permalink") or "", seen_at=(v.get("attackdate") or v.get("discovered") or "")[:10] or "",
        actor=group, org=org, country=v.get("country", ""), meta={"attribution": ATTRIBUTION},
    )


def fetch(offline: bool = True, limit: int = 100) -> list[Item]:
    data = load_sample("ransomware_live.json") if offline else cached_get(f"{BASE}/recentvictims")
    return [_to_item(v) for v in data[:limit]]
