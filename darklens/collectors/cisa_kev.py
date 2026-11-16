"""CISA Known Exploited Vulnerabilities (KEV) catalogue: software flaws that attackers are using right now.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog  (US government data, no key, no stated limits).
Please credit it: "Source: CISA Known Exploited Vulnerabilities Catalog".

The catalogue holds the whole history (about 1,800 entries), so only recently added ones are collected: a flaw
exploited in 2021 is not news. Each entry says whether ransomware groups are known to use it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import Item
from .base import cached_get

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTRIBUTION = "Source: CISA Known Exploited Vulnerabilities Catalog"


def _to_item(v: dict) -> Item:
    cve = v["cveID"]
    vendor, product = v.get("vendorProject") or "", v.get("product") or ""
    ransomware = (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
    text = (f"{cve}: {v.get('vulnerabilityName') or cve}. {v.get('shortDescription') or ''} "
            f"Affects {vendor} {product}. Known ransomware use: {'yes' if ransomware else 'no'}.").strip()
    return Item(source="cisa-kev", kind="advisory", title=f"{cve}: {vendor} {product}".strip(), text=text,
                url=f"https://nvd.nist.gov/vuln/detail/{cve}", seen_at=(v.get("dateAdded") or "")[:10],
                actor=vendor, meta={"ransomware": ransomware, "cve": cve, "attribution": ATTRIBUTION})


def fetch(offline: bool = True, days: int = 45, limit: int = 100) -> list[Item]:
    if offline:
        return []  # no demo samples: the demo set is about posts, and this needs no key to run live
    data = cached_get(URL)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise RuntimeError("Unexpected answer from the CISA catalogue.")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [v for v in vulns if isinstance(v, dict) and v.get("cveID") and (v.get("dateAdded") or "") >= cutoff]
    recent.sort(key=lambda v: v.get("dateAdded") or "", reverse=True)
    return [_to_item(v) for v in recent[:limit]]
