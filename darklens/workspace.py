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
    """The stored items that are about this workspace, scored against only this workspace's entries, worst first."""
    from . import pipeline

    entries = accounts.watch_list(con, wid)
    if not entries:
        return []
    wdom, wmail, wprod = split_entries(entries)
    clauses = " OR ".join(["LOWER(COALESCE(title,'') || ' ' || COALESCE(text,'')) LIKE ? ESCAPE '\\'"] * len(entries))
    rows = con.execute(f"SELECT * FROM items WHERE {clauses} ORDER BY seen_at DESC LIMIT {CANDIDATE_LIMIT}",
                       tuple(_like(e["value"]) for e in entries)).fetchall()
    clf = get_classifier()
    out = []
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        item = Item(source=r["source"], kind=r["kind"], title=r["title"] or "", text=r["text"] or "", url=r["url"] or "",
                    seen_at=r["seen_at"] or "", actor=r["actor"] or "", org=r["org"] or "", country=r["country"] or "", meta=meta)
        a = pipeline.analyse(item, wdom, wmail, clf, wprod)
        about_you = [s for s in a.signals if s.name.startswith(_WATCH_SIGNALS)]
        if a.score <= 0 or not about_you:
            continue
        restricted = bool(meta.get("no_redistribute"))
        out.append({"item_id": r["id"], "title": item.title, "source": item.source, "url": item.url, "seen_at": item.seen_at,
                    "org": item.org, "actor": item.actor, "category": a.category, "severity": a.severity, "score": a.score,
                    "demo": bool(meta.get("demo")), "restricted": restricted,
                    "text": "" if restricted else item.text[:300],
                    "matched": sorted({s.evidence for s in about_you if s.evidence}),
                    "reasons": [{"name": s.name, "why": s.why} for s in sorted(a.signals, key=lambda s: -s.score)[:4]]})
    out.sort(key=lambda x: (-x["score"], x["item_id"]))
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
    base = os.environ.get("PUBLIC_APP_URL", "").rstrip("/")
    why = a["reasons"][0]["why"] if a["reasons"] else ""
    link = f"\n{a['url']}" if a["url"] else ""
    return f"DarkLens {a['severity'].upper()} {a['score']}/100: {_clean(a['title'], 200)}\n{_clean(why, 300)}{link}" + (
        f"\n{base}/#/workspace" if base else "")


def post_webhook(url: str, text: str) -> None:
    import requests

    why = accounts.check_webhook_url(url)  # checked again at send time: a name can change what it points to
    if why:
        raise ValueError(why)
    r = requests.post(url, json={"text": text, "content": text}, timeout=10, allow_redirects=False)
    r.raise_for_status()


def dispatch_webhook(con, ws: dict) -> int:
    """Send this workspace's new alerts at or above its chosen level, at most WEBHOOK_MAX_PER_RUN, then one summary."""
    if not ws.get("webhook_url"):
        return 0
    floor = SEVERITY_RANK.get(ws.get("notify_min") or "high", 2)
    done = _sent(con, ws["id"], "webhook")
    todo = [a for a in personal_alerts(con, ws["id"], 100) if SEVERITY_RANK.get(a["severity"], 0) >= floor and a["item_id"] not in done]
    sent = 0
    for a in todo[:WEBHOOK_MAX_PER_RUN]:
        try:
            post_webhook(ws["webhook_url"], format_alert(a))
        except Exception as e:  # noqa: BLE001
            status = getattr(getattr(e, "response", None), "status_code", None)
            if isinstance(e, ValueError) or (isinstance(status, int) and 400 <= status < 500 and status not in (408, 429)):
                log.warning("workspace %s webhook rejected an alert (%s); skipping it", ws["id"], type(e).__name__)
                _mark(con, ws["id"], [a["item_id"]], "webhook")
                continue
            log.warning("workspace %s webhook failed: %s", ws["id"], type(e).__name__)
            break
        _mark(con, ws["id"], [a["item_id"]], "webhook")
        sent += 1
    else:
        rest = todo[WEBHOOK_MAX_PER_RUN:]
        if rest:
            try:
                post_webhook(ws["webhook_url"], f"DarkLens: {len(rest)} more alerts about your watchlist are waiting.")
                _mark(con, ws["id"], [a["item_id"] for a in rest], "webhook")
            except Exception as e:  # noqa: BLE001
                log.warning("workspace %s webhook summary failed: %s", ws["id"], type(e).__name__)
    return sent


def run_scheduled(con) -> dict:
    """After each collection: every workspace's webhook alerts, and any digest that is due. One workspace failing never
    stops the others."""
    webhooks = digests = 0
    for ws in accounts.all_workspaces(con):
        try:
            webhooks += dispatch_webhook(con, ws)
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
