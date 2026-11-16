"""Ingest -> extract -> classify -> score -> store. The whole system in one function."""
from __future__ import annotations

import json
from dataclasses import dataclass

from .breach.hibp import credential_exposure, mask_combolist
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


# Below this confidence a classifier-only guess is reported as "uncertain". Chosen from data, not by feel.
# First cut was 0.4 (everyday sentences scored 0.19-0.39). Measured on 234 real ordinary news items, 0.4 still let
# 31% of them raise a Low alert, because ordinary text often gets 40-60% confidence for "ransomware leak". The
# trade-off curve is flat from 0.6 up: at 0.6 only 2.6% raise an alert, for about 4 points of recall on synthetic
# threat posts (76.5% -> 72.4%). The 234 items were also used to find this, so the 2.6% is optimistic.
UNCERTAIN_BELOW = 0.6


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


def _watchlist_signals(low: str, iocs: dict, watch_domains: list[str], watch_emails: list[str]) -> list[Signal]:
    """Signals for text (already lower-cased) that mentions something on the watchlist."""
    out: list[Signal] = []
    found = " ".join(iocs.get("domain", []) + iocs.get("email", []))
    for d in watch_domains:
        if d.lower() in low or d.lower() in found:
            out.append(Signal("Watchlist domain match", 90, f"Mentions your watched domain {d}.", d, full=True))
    for e in watch_emails:
        if e.lower() in low:
            out.append(Signal("Watchlist email match", 85, f"Mentions your watched email {e}.", e, full=True))
    return out


def analyse(item: Item, watch_domains: list[str] | None = None, watch_emails: list[str] | None = None,
            clf=None) -> Analysis:
    clf = clf or get_classifier()
    watch_domains = watch_domains or []
    watch_emails = [e.lower() for e in (watch_emails or [])]
    text = f"{item.title}. {item.text}"

    iocs = extract_iocs(item.text)
    if item.kind == "ioc":
        # Feed indicators are evidence, not prose: score by the feed's own confidence, skip the text classifier.
        # One known-bad indicator is news about the internet, not about you, and a feed carries over a thousand a
        # day, so on its own it is capped to stay Low (the 0.55 generic discount puts 70 at 38). What makes one
        # matter is your watchlist: a listed domain or email of yours is a High or Critical alert.
        c = int(item.meta.get("confidence") or 50)
        sig = [Signal("Feed indicator", min(c, 70), f"Listed by {item.source} with confidence {c}.", item.actor)]
        sig += _watchlist_signals(f"{item.title}. {item.text}".lower(), iocs, watch_domains, watch_emails)
        score, sev = combine(sig)
        return Analysis("ioc_feed", c / 100, {}, sig, score, sev, iocs, [])
    if item.kind == "advisory":
        # A vulnerability the CISA catalogue says is being exploited. Real evidence, but about a product rather than
        # about you, so on its own it stays Low (60) or Medium when ransomware groups use it (80). Prose analysis
        # would only add noise, so the text model is skipped, as for indicators.
        ransomware = bool(item.meta.get("ransomware"))
        sig = [Signal("Exploited in the wild", 80 if ransomware else 60,
                      "CISA lists this flaw as exploited in real attacks" + (" and used by ransomware groups." if ransomware else "."),
                      item.meta.get("cve", ""))]
        sig += _watchlist_signals(f"{item.title}. {item.text}".lower(), iocs, watch_domains, watch_emails)
        score, sev = combine(sig)
        return Analysis("known_exploited", 0.95, {}, sig, score, sev, iocs, [])
    category, conf, probs = clf.classify(text)
    signals: list[Signal] = [s for _, s in run_rules(text)]
    rule_hits = len(signals)

    if item.kind == "leak_claim":
        # The source itself says this organisation was claimed by a ransomware group: that is evidence a text
        # model cannot see in a short, templated description, and it fixes the category.
        category, conf = "ransomware_leak", max(conf if category == "ransomware_leak" else 0.0, 0.9)
        signals.append(Signal("Listed on a leak-site tracker", 75,
                              f"{item.source} lists this organisation as a ransomware victim.", item.actor))

    # Watchlist: the highest-value signal, because it turns generic intel into "this is about us".
    exposures = credential_exposure(item.text, watch_domains)
    watch = _watchlist_signals(text.lower(), iocs, watch_domains, watch_emails)

    # Admit uncertainty. When the text model is the ONLY evidence and it is not confident, say "not sure" instead of
    # attaching a threat label to what is most likely ordinary text (on everyday sentences it guessed a threat type
    # at 19-39% confidence). Anything backed by a rule, the watchlist, or leaked credentials is unaffected.
    weak_guess = (item.kind != "leak_claim" and category not in ("benign", "uncertain") and conf < UNCERTAIN_BELOW
                  and rule_hits == 0)
    if weak_guess and not watch and not exposures:
        return Analysis("uncertain", conf, probs, [], 0, "low", iocs, exposures)
    if weak_guess:
        # It mentions something of yours, so it still raises an alert, but we do not know what kind of post it is.
        # Do not pin a threat label on it, and do not let the weak guess add to the score.
        category = "uncertain"
    elif category != "benign":
        signals.append(Signal("Classifier", int(CATEGORY_BASE[category] * conf), f"Text looks like '{category}' (confidence {conf:.0%}).", category))
    signals += watch
    if exposures:
        signals.append(Signal("Credentials for watched domain", 95,
                              f"{len(exposures)} email:password pairs for your domains appear in this item.",
                              exposures[0]["email"], full=True))
    # Payment address next to a non-benign category: monetisation marker.
    if category not in ("benign", "uncertain") and any(t in iocs for t in ("btc", "eth", "xmr", "trx")):
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
    if offline:
        for it in items:
            it.meta["demo"] = True  # synthetic sample data, shown with a Demo badge
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
        it.text = mask_combolist(it.text)  # never persist plaintext passwords
        db.upsert_item(con, it)
        db.add_iocs(con, it.id, a.iocs)
        if a.score > 0:
            db.upsert_alert(con, it.id, a.category, a.confidence, a.score, a.severity, a.signals, a.probs, now_iso())
            n_alerts += 1
        else:
            db.alert_delete(con, it.id)  # no longer an alert (for example, now "uncertain"): remove a stale one
    con.commit()
    return {"items": len(items), "alerts": n_alerts}


def rescore(con) -> dict:
    """Re-score every stored item (demo and live) against the current watchlist, without collecting anything.

    Stored text already has passwords masked, but the masked pairs still parse, so watchlist exposure is found.
    Items keep their stored id, because the id is a hash of the original unmasked text.
    """
    clf = get_classifier()
    wl = db.watch_all(con)
    wdom = [v for k, v in wl if k == "domain"]
    wmail = [v for k, v in wl if k == "email"]
    n = 0
    for r in con.execute("SELECT * FROM items").fetchall():
        it = Item(source=r["source"], kind=r["kind"], title=r["title"] or "", text=r["text"] or "", url=r["url"] or "",
                  seen_at=r["seen_at"] or "", actor=r["actor"] or "", org=r["org"] or "", country=r["country"] or "",
                  meta=json.loads(r["meta"] or "{}"))
        a = analyse(it, wdom, wmail, clf)
        db.add_iocs(con, r["id"], a.iocs)
        if a.score > 0:
            db.upsert_alert(con, r["id"], a.category, a.confidence, a.score, a.severity, a.signals, a.probs, now_iso())
            n += 1
        else:
            db.alert_delete(con, r["id"])
    con.commit()
    return {"items": len(con.execute("SELECT id FROM items").fetchall()), "alerts": n}
