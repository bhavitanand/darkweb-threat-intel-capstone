"""What a workspace sees: alerts about ITS OWN watchlist, a digest of what is new, and an alert webhook.

Alerts are stored once and are global. A private watchlist must never change what other people see, so it is applied
here, when asked: the stored items that mention one of the workspace's entries are re-scored against only that
workspace's entries. Nothing is written back to the alerts table.

Text a source forbids re-publishing (Ransomware.live, news feeds) is never included, only the title, score, reasons and a
link to the source, exactly as on the public pages.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone

from . import accounts, mailer
from .models import Item, now_iso
from .nlp.classifier import get_classifier
from .store import db

log = logging.getLogger("darklens.workspace")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CANDIDATE_LIMIT = 300      # the most recent stored items that mention an entry are examined
DIGEST_MAX_LINES = 15
WEBHOOK_MAX_PER_RUN = 10
_WATCH_SIGNALS = ("Watchlist", "Watched", "Credentials for watched")


def _like(value: str) -> str:
    return "%" + value.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def split_entries(entries: list[dict]) -> tuple[list[str], list[str], list[str]]:
    pick = lambda k: [e["value"] for e in entries if e["kind"] == k]  # noqa: E731
    return pick("domain"), pick("email"), pick("product")


def personal_alerts(con, wid: str, limit: int = 100) -> list[dict]:
    """The stored items that are about this workspace, worst first.

    An item is "about you" when it mentions one of the workspace's watchlist entries, or matches one of its alert rules
    (darklens/alert_rules.py). It is re-scored against this workspace's own entries and the software named in its rules,
    so "you run this product and it is being attacked" lifts the score here without changing what anyone else sees."""
    from . import alert_rules, pipeline

    entries = accounts.watch_list(con, wid)
    rules = alert_rules.list_rules(con, wid)
    if not entries and not rules:
        return []
    wdom, wmail, wprod = split_entries(entries)
    rule_prod = sorted({p for r in rules for p in r["spec"]["products"] if len(p) >= 3})
    rule_dom = sorted({d for r in rules for d in r["spec"]["domains"]})
    rule_mail = sorted({e for r in rules for e in r["spec"]["emails"]})

    terms = [e["value"] for e in entries] + [t for r in rules for t in alert_rules.search_terms(r["spec"])]
    terms = sorted(set(t.lower() for t in terms if t))
    cats = sorted({c for r in rules for c in r["spec"]["categories"]})
    clauses = ["LOWER(COALESCE(i.title,'') || ' ' || COALESCE(i.text,'')) LIKE ? ESCAPE '\\'"] * len(terms)
    params: list = [_like(t) for t in terms]
    if cats:
        clauses.append(f"a.category IN ({','.join('?' * len(cats))})")
        params += cats
    if not clauses:
        return []
    rows = con.execute(f"SELECT i.*, a.category AS a_category FROM items i LEFT JOIN alerts a ON a.item_id=i.id "
                       f"WHERE {' OR '.join(clauses)} ORDER BY i.seen_at DESC LIMIT {CANDIDATE_LIMIT}", tuple(params)).fetchall()
    clf = get_classifier()
    out = []
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        item = Item(source=r["source"], kind=r["kind"], title=r["title"] or "", text=r["text"] or "", url=r["url"] or "",
                    seen_at=r["seen_at"] or "", actor=r["actor"] or "", org=r["org"] or "", country=r["country"] or "", meta=meta)
        a = pipeline.analyse(item, sorted(set(wdom + rule_dom)), sorted(set(wmail + rule_mail)), clf, sorted(set(wprod + rule_prod)))
        if a.score <= 0:
            continue
        low = f"{item.title}. {item.text}".lower()
        about_you = [s for s in a.signals if s.name.startswith(_WATCH_SIGNALS)]
        entry_hits = sorted({s.evidence for s in about_you if s.evidence and s.evidence in {e["value"] for e in entries}})
        if entries and about_you and not entry_hits:
            # a watch signal whose evidence is not literally an entry (e.g. credentials for a watched domain)
            entry_hits = [e["value"] for e in entries if e["value"] in low][:3]
        rule_hits = []
        for rule in rules:
            ev = alert_rules.match(rule["spec"], low, a.category, a.severity)
            if ev is not None:
                rule_hits.append({"id": rule["id"], "prompt": rule["prompt"], "evidence": ev[:6]})
        if not entry_hits and not rule_hits:
            continue
        restricted = bool(meta.get("no_redistribute"))
        out.append({"item_id": r["id"], "title": item.title, "source": item.source, "url": item.url, "seen_at": item.seen_at,
                    "org": item.org, "actor": item.actor, "category": a.category, "severity": a.severity, "score": a.score,
                    "demo": bool(meta.get("demo")), "restricted": restricted,
                    "text": "" if restricted else item.text[:300],
                    "matched": sorted(set(entry_hits) | {w for h in rule_hits for w in h["evidence"]}),
                    "watch_hits": entry_hits, "rules": rule_hits,
                    "reasons": [{"name": s.name, "why": s.why} for s in sorted(a.signals, key=lambda s: -s.score)[:4]]})
    out.sort(key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), -x["score"], x["item_id"]))
    return out[:max(limit, 0)]


# ---------------- digest ----------------

def digest_due(ws: dict, now: datetime | None = None) -> bool:
    gap = {"daily": timedelta(hours=22), "weekly": timedelta(days=6, hours=20)}.get(ws.get("digest") or "off")
    if gap is None:
        return False
    last = ws.get("digest_sent_at") or ""
    if not last:
        return True
    try:
        return (now or datetime.now(timezone.utc)) - datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) >= gap
    except ValueError:
        return True


def _sent(con, wid: str, channel: str) -> set[str]:
    return {r["item_id"] for r in con.execute("SELECT item_id FROM ws_notified WHERE workspace_id=? AND channel=?", (wid, channel))}


def _mark(con, wid: str, ids: list[str], channel: str) -> None:
    for i in ids:
        con.execute(db._upsert("ws_notified", ["workspace_id", "item_id", "channel", "created_at"], ["workspace_id", "item_id", "channel"]),
                    (wid, i, channel, now_iso()))
    con.commit()


def _clean(s, limit: int) -> str:
    return " ".join("".join(" " if (ch.isspace() or ord(ch) < 32) else ch for ch in str(s or "")).split())[:limit]


def build_digest(con, wid: str) -> tuple[str, str, list[str]]:
    """(subject, body, item ids) for what is new since the last digest. An empty id list means nothing is new."""
    new = [a for a in personal_alerts(con, wid, 200) if a["item_id"] not in _sent(con, wid, "digest")]
    if not new:
        return "", "", []
    base = os.environ.get("PUBLIC_APP_URL", "").rstrip("/")
    lines = [f"DarkLens found {len(new)} new item{'' if len(new) == 1 else 's'} about the things you watch.", ""]
    for a in new[:DIGEST_MAX_LINES]:
        why = a["reasons"][0]["why"] if a["reasons"] else ""
        lines.append(f"[{a['severity'].upper()} {a['score']}] {_clean(a['title'], 140)}")
        if why:
            lines.append(f"    {_clean(why, 200)}")
        if a["url"]:
            lines.append(f"    {a['url']}")
    if len(new) > DIGEST_MAX_LINES:
        lines.append(f"... and {len(new) - DIGEST_MAX_LINES} more.")
    lines += ["", "A score is a guide to where to look first, not proof that something happened.",
              f"Change or stop this digest any time in your workspace: {base}/#/workspace" if base else
              "Change or stop this digest any time in your DarkLens workspace."]
    return f"DarkLens digest: {len(new)} new about your watchlist", "\n".join(lines), [a["item_id"] for a in new]


def send_digest(con, ws: dict, email: str) -> int:
    """Email the digest if anything is new. Returns how many items it covered (0 if none). Raises MailError on failure."""
    subject, body, ids = build_digest(con, ws["id"])
    if not ids:
        return 0
    mailer.send(email, subject, body)
    _mark(con, ws["id"], ids, "digest")
    return len(ids)


# ---------------- webhook ----------------

def format_alert(a: dict) -> str:
    """One alert as a short chat message: severity and score, the title, why it is about you, and the original report."""
    base = os.environ.get("PUBLIC_APP_URL", "").rstrip("/")
    why = a["reasons"][0]["why"] if a["reasons"] else ""
    because = ""
    if a.get("rules"):
        because = "\nYou asked: \"" + _clean(a["rules"][0]["prompt"], 120) + "\""
    elif a.get("matched"):
        because = "\nMatches your watchlist: " + _clean(", ".join(a["matched"][:4]), 120)
    link = f"\nRead the original report: {a['url']}" if a["url"] else ""
    head = f"DarkLens {a['severity'].upper()} {a['score']}/100: {_clean(a['title'], 200)}"
    return f"{head}\n{_clean(why, 300)}{because}{link}" + (f"\n{base}/#/alerts/{a['item_id']}" if base else "")


def post_webhook(url: str, text: str, kind: str = "") -> None:
    """Post one message. Slack and Teams read `text`, Discord reads `content`; a plain webhook gets both."""
    import requests

    why = accounts.check_webhook_url(url)  # checked again at send time: a name can change what it points to
    if why:
        raise ValueError(why)
    body = {"content": text[:1990]} if kind == "discord" else {"text": text} if kind in ("slack", "teams") else {"text": text, "content": text}
    r = requests.post(url, json=body, timeout=10, allow_redirects=False)
    r.raise_for_status()


def _post(url: str, text: str, kind: str) -> None:
    if kind:
        post_webhook(url, text, kind)
    else:
        post_webhook(url, text)


def _deliver(con, ws: dict, url: str, kind: str, channel: str, floor_name: str) -> int:
    """Send this workspace's new alerts at or above `floor_name` to one address, most severe first, at most
    WEBHOOK_MAX_PER_RUN, then one summary line for the rest."""
    floor = SEVERITY_RANK.get(floor_name or "high", 2)
    done = _sent(con, ws["id"], channel)
    todo = [a for a in personal_alerts(con, ws["id"], 100) if SEVERITY_RANK.get(a["severity"], 0) >= floor and a["item_id"] not in done]
    todo.sort(key=lambda a: (-SEVERITY_RANK.get(a["severity"], 0), -a["score"]))
    sent = 0
    for a in todo[:WEBHOOK_MAX_PER_RUN]:
        try:
            _post(url, format_alert(a), kind)
        except Exception as e:  # noqa: BLE001
            status = getattr(getattr(e, "response", None), "status_code", None)
            if isinstance(e, ValueError) or (isinstance(status, int) and 400 <= status < 500 and status not in (408, 429)):
                log.warning("workspace %s %s rejected an alert (%s); skipping it", ws["id"], channel, type(e).__name__)
                _mark(con, ws["id"], [a["item_id"]], channel)
                continue
            log.warning("workspace %s %s failed: %s", ws["id"], channel, type(e).__name__)
            break
        _mark(con, ws["id"], [a["item_id"]], channel)
        sent += 1
    else:
        rest = todo[WEBHOOK_MAX_PER_RUN:]
        if rest:
            try:
                _post(url, f"DarkLens: {len(rest)} more alerts about what you watch are waiting.", kind)
                _mark(con, ws["id"], [a["item_id"] for a in rest], channel)
            except Exception as e:  # noqa: BLE001
                log.warning("workspace %s %s summary failed: %s", ws["id"], channel, type(e).__name__)
    return sent


def dispatch_connectors(con, ws: dict) -> int:
    """Every Slack, Discord and Teams connector of this workspace. One failing never stops the others."""
    sent = 0
    for c in accounts.connectors(con, ws["id"]):
        try:
            sent += _deliver(con, ws, c["url"], c["kind"], f"connector:{c['kind']}", c["min_severity"])
        except Exception as e:  # noqa: BLE001
            log.warning("workspace %s connector %s failed: %s", ws["id"], c["kind"], type(e).__name__)
    return sent


def dispatch_webhook(con, ws: dict) -> int:
    """The original single "alert webhook" setting (kept for API compatibility; the website now uses connectors)."""
    if not ws.get("webhook_url"):
        return 0
    return _deliver(con, ws, ws["webhook_url"], "", "webhook", ws.get("notify_min") or "high")


def run_scheduled(con) -> dict:
    """After each collection: every workspace's webhook alerts, and any digest that is due. One workspace failing never
    stops the others."""
    webhooks = digests = 0
    for ws in accounts.all_workspaces(con):
        try:
            webhooks += dispatch_webhook(con, ws)
            webhooks += dispatch_connectors(con, ws)
        except Exception as e:  # noqa: BLE001
            log.warning("workspace %s alerts failed: %s", ws["id"], type(e).__name__)
        try:
            if mailer.configured() and digest_due(ws):
                digests += 1 if send_digest(con, ws, ws["owner_email"]) else 0
                con.execute("UPDATE workspaces SET digest_sent_at=? WHERE id=?", (now_iso(), ws["id"]))
                con.commit()
        except Exception as e:  # noqa: BLE001
            log.warning("workspace %s digest failed: %s", ws["id"], type(e).__name__)
    return {"webhook_alerts": webhooks, "digests": digests}
