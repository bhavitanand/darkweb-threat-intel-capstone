from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Item:
    """One normalised piece of collected intelligence (a post, victim claim, IOC, page snippet)."""

    source: str                 # e.g. "ransomware.live", "threatfox", "tor:allowlisted"
    kind: str                   # "leak_claim" | "ioc" | "post" | "page"
    text: str                   # snippet only, never a full page
    title: str = ""
    url: str = ""
    seen_at: str = field(default_factory=now_iso)
    actor: str = ""             # ransomware group / forum handle if known
    org: str = ""               # claimed victim organisation, if any
    country: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        raw = "|".join([self.source, self.kind, self.title, self.text[:200], self.url])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d


@dataclass
class Signal:
    """One explainable reason contributing to an alert score."""

    name: str
    score: int          # 0-100 strength of this single signal
    why: str            # plain-English reason
    evidence: str = ""  # the matched text / value, truncated
    full: bool = False  # True = counts at full strength (watchlist hits are about "us")

    def to_dict(self) -> dict:
        return asdict(self)
