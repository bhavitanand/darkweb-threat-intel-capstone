"""Optional alerts to people. Off unless a channel is configured through environment variables.

Channels (either, both, or neither):
  webhook  ALERT_WEBHOOK_URL            Slack, Discord, Teams or any URL that accepts a JSON POST
  email    SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD ALERT_EMAIL_TO [ALERT_EMAIL_FROM]

What triggers a message (NOTIFY_MIN): "watchlist" (default, only alerts about your own domains or emails),
"critical" (plus critical alerts) or "high" (plus high alerts). Synthetic demo data never sends anything.
Each alert is sent once per channel, and a single run sends at most MAX_PER_RUN messages plus one summary.
Secrets live only in the environment and are never logged or included in a message.
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage

from .models import now_iso
from .store import db

log = logging.getLogger("darklens.notify")
MAX_PER_RUN = 10
WATCH_SIGNALS = ("Watchlist", "Credentials for watched")
LEVELS = {"watchlist": set(), "critical": {"critical"}, "high": {"critical", "high"}}


def channels() -> list[str]:
    out = []
    if os.environ.get("ALERT_WEBHOOK_URL"):
        out.append("webhook")
    if os.environ.get("SMTP_HOST") and os.environ.get("ALERT_EMAIL_TO"):
        out.append("email")
    return out


def _is_watch_hit(signals: list[dict]) -> bool:
    return any(s["name"].startswith(WATCH_SIGNALS) for s in signals)


def pending(con, channel: str) -> list[dict]:
    """Alerts that deserve a message and have not been sent on this channel yet, worst first."""
    import json

    level = LEVELS.get(os.environ.get("NOTIFY_MIN", "watchlist").strip().lower(), set())
    out = []
    for r in con.execute("SELECT a.item_id, a.score, a.severity, a.signals, i.title, i.meta FROM alerts a "
                         "JOIN items i ON i.id=a.item_id ORDER BY a.score DESC"):
        meta = json.loads(r["meta"] or "{}")
        if meta.get("demo") and os.environ.get("NOTIFY_DEMO") != "1":
            continue
        signals = json.loads(r["signals"])
        if not (_is_watch_hit(signals) or r["severity"] in level):
            continue
        if db.notified_has(con, r["item_id"], channel):
            continue
        top = max(signals, key=lambda s: s["score"]) if signals else None
        out.append({"id": r["item_id"], "score": r["score"], "severity": r["severity"], "title": r["title"],
                    "why": (top["why"] if top else ""), "watch": _is_watch_hit(signals)})
    return out


def format_message(a: dict) -> str:
    base = os.environ.get("PUBLIC_APP_URL", "").rstrip("/")
    link = f"\n{base}/#/alerts/{a['id']}" if base else ""
    kind = "About your watchlist. " if a["watch"] else ""
    return f"DarkLens {a['severity'].upper()} {a['score']}/100: {a['title']}\n{kind}{a['why']}{link}"


def send_webhook(url: str, text: str) -> None:
    import requests

    r = requests.post(url, json={"text": text, "content": text}, timeout=15)  # Slack reads text, Discord content
    r.raise_for_status()


def send_email(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("ALERT_EMAIL_FROM") or os.environ.get("SMTP_USER") or "darklens@localhost"
    msg["To"] = os.environ["ALERT_EMAIL_TO"]
    msg.set_content(body)
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=20) as s:
        if port != 25:
            s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        s.send_message(msg)


def _send(channel: str, text: str) -> None:
    if channel == "webhook":
        send_webhook(os.environ["ALERT_WEBHOOK_URL"], text)
    else:
        send_email(text.splitlines()[0][:150], text)


def dispatch(con) -> int:
    """Send what is pending on every configured channel. Failures are logged and retried on the next run."""
    sent = 0
    for ch in channels():
        todo = pending(con, ch)
        for a in todo[:MAX_PER_RUN]:
            try:
                _send(ch, format_message(a))
            except Exception as e:  # noqa: BLE001
                log.warning("notify %s failed: %s", ch, type(e).__name__)
                break  # the channel is probably down; try again next run
            db.notified_add(con, a["id"], ch, now_iso())
            sent += 1
        else:
            rest = todo[MAX_PER_RUN:]
            if rest:
                try:
                    _send(ch, f"DarkLens: {len(rest)} more alerts are waiting. Open the site to review them.")
                    for a in rest:
                        db.notified_add(con, a["id"], ch, now_iso())
                except Exception as e:  # noqa: BLE001
                    log.warning("notify %s summary failed: %s", ch, type(e).__name__)
    return sent
