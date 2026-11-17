"""CISA Known Exploited Vulnerabilities (KEV) catalogue: software flaws that attackers are using right now.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog  (US government data, no key, no stated limits).
Please credit it: "Source: CISA Known Exploited Vulnerabilities Catalog".

The catalogue holds the whole history (about 1,800 entries), so only recently added ones are collected: a flaw
exploited in 2021 is not news. Each entry says whether ransomware groups are known to use it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import Item
from .base import cached_get, text

EPSS_URL = "https://api.first.org/data/v1/epss?cve="

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTRIBUTION = "Source: CISA Known Exploited Vulnerabilities Catalog"


def _to_item(v: dict) -> Item:
    cve = text(v.get("cveID"), 40)
    vendor, product = text(v.get("vendorProject"), 120), text(v.get("product"), 120)
    ransomware = text(v.get("knownRansomwareCampaignUse"), 20).lower() == "known"
    body = (f"{cve}: {text(v.get('vulnerabilityName')) or cve}. {text(v.get('shortDescription'))} "
            f"Affects {vendor} {product}. Known ransomware use: {'yes' if ransomware else 'no'}.").strip()
    return Item(source="cisa-kev", kind="advisory", title=f"{cve}: {vendor} {product}".strip(), text=body,
                url=f"https://nvd.nist.gov/vuln/detail/{cve}", seen_at=text(v.get("dateAdded"))[:10],
                actor=vendor, meta={"ransomware": ransomware, "cve": cve, "attribution": ATTRIBUTION})


def fetch(offline: bool = True, days: int = 45, limit: int = 100) -> list[Item]:
    if offline:
        return []  # no demo samples: the demo set is about posts, and this needs no key to run live
    data = cached_get(URL)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise RuntimeError("Unexpected answer from the CISA catalogue.")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [v for v in vulns if isinstance(v, dict) and text(v.get("cveID")) and text(v.get("dateAdded")) >= cutoff]
    recent.sort(key=lambda v: text(v.get("dateAdded")), reverse=True)
    items = [_to_item(v) for v in recent[:max(limit, 0)]]
    scores = epss_scores([it.meta["cve"] for it in items])
    for it in items:
        if it.meta["cve"] in scores:
            it.meta["epss"], it.meta["epss_percentile"] = scores[it.meta["cve"]]
    return items


def epss_scores(cves: list[str]) -> dict[str, tuple[float, float]]:
    """FIRST's Exploit Prediction Scoring System (public, no key): the modelled chance each flaw is exploited in the next
    30 days. Optional enrichment: if the service is down or answers oddly the items are simply used without it."""
    out: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cves), 100):
        try:
            data = cached_get(EPSS_URL + ",".join(cves[i:i + 100]), ttl=6 * 3600)
        except Exception:  # noqa: BLE001
            continue
        rows = data.get("data") if isinstance(data, dict) else None
        for row in rows if isinstance(rows, list) else []:
            try:
                out[text(row["cve"], 40)] = (round(float(row["epss"]), 5), round(float(row["percentile"]), 5))
            except (KeyError, TypeError, ValueError):
                continue
    return out
