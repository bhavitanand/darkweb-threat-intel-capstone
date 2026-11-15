"""Ingest -> extract -> classify -> score -> store. The whole system in one function."""
from __future__ import annotations

import json
from dataclasses import dataclass

from .breach.hibp import credential_exposure
from .collectors import forums, ransomware_live, threatfox
from .extract.iocs import extract_iocs
from .models import Item, Signal, now_iso
from .nlp.classifier import get_classifier
from .rules.engine import run_rules
from .scoring import combine
from .store import db

# How much each category matters on its own, before evidence from rules and watchlists is added.
CATEGORY_BASE = {
    "ransomware_leak": 55, "credential_dump": 50, "exploit_sale": 55, "phishing_kit": 40,
    "malware_sale": 45, "carding_fraud": 35, "threat_chatter": 30, "benign": 0,
}


@dataclass
class Analysis:
    category: str
    confidence: float
    probs: dict
    signals: list[Signal]
    score: int
    severity: str
    iocs: dict
    exposures: list


def analyse(item: Item, watch_domains: list[str] | None = None, watch_emails: list[str] | None = None,
            clf=None) -> Analysis:
    clf = clf or get_classifier()
    watch_domains = watch_domains or []
    watch_emails = [e.lower() for e in (watch_emails or [])]
    text = f"{item.title}. {item.text}"

    iocs = extract_iocs(item.text)
    if item.kind == "ioc":
        # Feed indicators are evidence, not prose: score by the feed's own confidence, skip the text classifier.
        c = int(item.meta.get("confidence") or 50)
        sig = [Signal("Feed indicator", c, f"Listed by {item.source} with confidence {c}.", item.actor)]
        score, sev = combine(sig)
        return Analysis("ioc_feed", c / 100, {}, sig, score, sev, iocs, [])
    category, conf, probs = clf.classify(text)
    signals: list[Signal] = [s for _, s in run_rules(text)]

    if category != "benign":
        signals.append(Signal("Classifier", int(CATEGORY_BASE[category] * conf), f"Text looks like '{category}' (confidence {conf:.0%}).", category))

    # Watchlist: the highest-value signal, because it turns generic intel into "this is about us".
    exposures = credential_exposure(item.text, watch_domains)
    low = text.lower()
    for d in watch_domains:
        if d.lower() in low or d.lower() in " ".join(iocs.get("domain", []) + iocs.get("email", [])):
            signals.append(Signal("Watchlist domain match", 90, f"Mentions your watched domain {d}.", d, full=True))
    for e in watch_emails:
        if e in low:
            signals.append(Signal("Watchlist email match", 85, f"Mentions your watched email {e}.", e, full=True))
    if exposures:
        signals.append(Signal("Credentials for watched domain", 95,
                              f"{len(exposures)} email:password pairs for your domains appear in this item.",
                              exposures[0]["email"], full=True))
    # Payment address next to a non-benign category: monetisation marker.
    if category != "benign" and any(t in iocs for t in ("btc", "eth", "xmr", "trx")):
        signals.append(Signal("Payment address present", 30, "A crypto address is attached, so this is a monetised offer.", ""))
    if category == "benign" and not signals:
        return Analysis(category, conf, probs, [], 0, "low", iocs, exposures)

    score, sev = combine(signals)
    return Analysis(category, conf, probs, signals, score, sev, iocs, exposures)


def collect(offline: bool = True) -> list[Item]:
    items: list[Item] = []
    items += ransomware_live.fetch(offline=offline)
    items += threatfox.fetch(offline=offline)
    items += forums.fetch(offline=offline)
    return items


def run(offline: bool = True, con=None, items: list[Item] | None = None) -> dict:
    con = con or db.connect()
    clf = get_classifier()
    wl = db.watch_all(con)
    wdom = [v for k, v in wl if k == "domain"]
    wmail = [v for k, v in wl if k == "email"]
    items = items if items is not None else collect(offline)
    n_alerts = 0
    for it in items:
        a = analyse(it, wdom, wmail, clf)
        db.upsert_item(con, it)
        db.add_iocs(con, it.id, a.iocs)
        if a.score > 0:
            db.upsert_alert(con, it.id, a.category, a.confidence, a.score, a.severity, a.signals, a.probs, now_iso())
            n_alerts += 1
    con.commit()
    return {"items": len(items), "alerts": n_alerts}
