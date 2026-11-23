"""GitHub reviewed security advisories (open-source package vulnerabilities).

Source: https://docs.github.com/en/rest/security-advisories/global-advisories. Public data (CC BY 4.0), works without a
key at 60 requests an hour; `GITHUB_TOKEN`, if set, lifts that. Credit: "Source: GitHub Advisory Database".
Advisories are ordinary vulnerability notices, so they are kind "advisory": Low unless they name something on your
watchlist (for example a package you run).
"""
from __future__ import annotations

import os

from ..models import Item
from .base import cached_get, text

URL = "https://api.github.com/advisories?type=reviewed&per_page={n}&sort=published&direction=desc"
ATTRIBUTION = "Source: GitHub Advisory Database (github.com/advisories), CC BY 4.0"


def parse(data, limit: int = 60) -> list[Item]:
    if not isinstance(data, list):
        raise RuntimeError("Unexpected answer from GitHub advisories.")
    out = []
    for a in data:
        if not isinstance(a, dict) or len(out) >= max(limit, 0):
            continue
        ghsa = text(a.get("ghsa_id"), 40)
        if not ghsa or a.get("withdrawn_at"):
            continue
        pkgs = []
        for v in a.get("vulnerabilities") or []:
            p = v.get("package") if isinstance(v, dict) else None
            name = text(p.get("name"), 100) if isinstance(p, dict) else ""
            if name and name not in pkgs:
                pkgs.append(name)
        cve = text(a.get("cve_id"), 40)
        summary = text(a.get("summary"), 300) or ghsa
        body = (f"{cve or ghsa}: {summary}. Severity {text(a.get('severity'), 12) or 'unknown'}. "
                f"Affects {', '.join(pkgs[:8]) or 'open-source packages'}. {text(a.get('description'), 600)}").strip()
        out.append(Item(source="github-advisories", kind="advisory", title=f"{cve or ghsa}: {summary}"[:200], text=body,
                        url=text(a.get("html_url"), 300), seen_at=text(a.get("published_at"))[:10],
                        actor=pkgs[0] if pkgs else "", meta={"cve": cve, "ghsa": ghsa, "attribution": ATTRIBUTION}))
    return out


def fetch(offline: bool = True, limit: int = 60) -> list[Item]:
    if offline:
        return []
    token = os.getenv("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
    return parse(cached_get(URL.format(n=min(max(limit, 1), 100)), ttl=3600, headers=headers), limit)
