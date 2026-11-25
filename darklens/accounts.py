"""Accounts, private workspaces, API keys and magic-link sign-in.

There are no passwords. A person enters an email address, receives a single-use link that works for 15 minutes, and
following it signs them in for 30 days. Every secret (sign-in link token, session token, API key) is random, shown or
sent once, and stored only as a SHA-256 hash, so a copy of the database cannot be used to sign in.

Each user has one private workspace: a watchlist only they can see, a digest setting, an optional alert webhook and API
keys. Alerts themselves stay global; what a workspace sees is computed from its own entries when asked
(darklens/workspace.py), so one person's watchlist never changes what anyone else sees.

Deliberately not revealed: whether an email already has an account (every sign-in request answers the same way).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import socket
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .store import db

LOGIN_TTL_MINUTES = 15
SESSION_DAYS = 30
MAX_SESSIONS_PER_USER = 10
MAX_LOGINS_PER_EMAIL_PER_HOUR = 5
WORKSPACE_WATCH_MAX = 50
MAX_API_KEYS = 5
DIGEST_CHOICES = ("off", "daily", "weekly")
NOTIFY_CHOICES = ("low", "medium", "high", "critical")

_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_DOMAIN = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_WEMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PRODUCT = re.compile(r"^[a-z0-9][a-z0-9 .+_#-]{1,58}[a-z0-9+#]$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_secret(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def normalise_email(raw) -> str | None:
    """A cleaned, lower-cased address, or None. No spaces, no control characters, bounded length."""
    if not isinstance(raw, str):
        return None
    e = raw.strip().lower()
    return e if len(e) <= 254 and _EMAIL.match(e) and ".." not in e else None


# ---------------- sign-in links ----------------

def request_login(con, email: str) -> str | None:
    """Create a sign-in token for `email` and return it (to be emailed), or None when this address has asked too often.
    The caller answers the same either way, so nobody can use this to probe which addresses are registered."""
    since = _iso(_now() - timedelta(hours=1))
    n = con.execute("SELECT COUNT(*) AS c FROM login_tokens WHERE email=? AND created_at>?", (email, since)).fetchone()["c"]
    if n >= MAX_LOGINS_PER_EMAIL_PER_HOUR:
        return None
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO login_tokens (token_hash, email, created_at, expires_at, used) VALUES (?,?,?,?,0)",
                (hash_secret(token), email, _iso(_now()), _iso(_now() + timedelta(minutes=LOGIN_TTL_MINUTES))))
    con.execute("DELETE FROM login_tokens WHERE expires_at<?", (_iso(_now() - timedelta(days=1)),))  # tidy old ones
    con.commit()
    return token


def verify_login(con, token: str) -> tuple[dict, str] | None:
    """Spend a sign-in token. Returns (user, session_token) or None for an unknown, used or expired token."""
    if not isinstance(token, str) or not (20 <= len(token) <= 200):
        return None
    h = hash_secret(token)
    row = con.execute("SELECT email, expires_at, used FROM login_tokens WHERE token_hash=?", (h,)).fetchone()
    if row is None or row["used"] or row["expires_at"] < _iso(_now()):
        return None
    con.execute("UPDATE login_tokens SET used=1 WHERE token_hash=?", (h,))
    user = _get_or_create_user(con, row["email"])
    ensure_workspace(con, user["id"])
    session = _new_session(con, user["id"])
    con.commit()
    return user, session


def _get_or_create_user(con, email: str) -> dict:
    row = con.execute("SELECT id, email, created_at FROM users WHERE email=?", (email,)).fetchone()
    if row:
        return dict(row)
    uid = "u_" + uuid.uuid4().hex[:16]
    con.execute("INSERT INTO users (id, email, created_at) VALUES (?,?,?)", (uid, email, _iso(_now())))
    return {"id": uid, "email": email, "created_at": _iso(_now())}


def _new_session(con, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                (hash_secret(token), user_id, _now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),  # microseconds: "newest" must be unambiguous
                 _iso(_now() + timedelta(days=SESSION_DAYS))))
    # Keep only the newest few sessions per user, and drop expired ones.
    con.execute("DELETE FROM sessions WHERE expires_at<?", (_iso(_now()),))
    old = [r["token_hash"] for r in con.execute(
        "SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC, token_hash", (user_id,))][MAX_SESSIONS_PER_USER:]
    for h in old:
        con.execute("DELETE FROM sessions WHERE token_hash=?", (h,))
    return token


def session_user(con, token: str | None) -> dict | None:
    if not isinstance(token, str) or not (20 <= len(token) <= 200):
        return None
    row = con.execute("SELECT u.id, u.email, u.created_at, s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id "
                      "WHERE s.token_hash=?", (hash_secret(token),)).fetchone()
    if row is None or row["expires_at"] < _iso(_now()):
        return None
    return {"id": row["id"], "email": row["email"], "created_at": row["created_at"]}


def end_session(con, token: str | None) -> None:
    if isinstance(token, str):
        con.execute("DELETE FROM sessions WHERE token_hash=?", (hash_secret(token),))
        con.commit()


def delete_account(con, user_id: str) -> None:
    """Remove a user and everything that belongs to them: workspace, entries, keys, sessions, sent-log."""
    ws = [r["id"] for r in con.execute("SELECT id FROM workspaces WHERE owner_id=?", (user_id,))]
    email = (con.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone() or {"email": None})["email"]
    for w in ws:
        for table in ("ws_watch", "api_keys", "ws_notified", "ws_rules", "ws_connectors"):
            con.execute(f"DELETE FROM {table} WHERE workspace_id=?", (w,))
        con.execute("DELETE FROM workspaces WHERE id=?", (w,))
    con.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    if email:
        con.execute("DELETE FROM login_tokens WHERE email=?", (email,))
    con.execute("DELETE FROM users WHERE id=?", (user_id,))
    con.commit()


# ---------------- workspaces ----------------

def ensure_workspace(con, user_id: str) -> dict:
    row = con.execute("SELECT * FROM workspaces WHERE owner_id=? ORDER BY created_at LIMIT 1", (user_id,)).fetchone()
    if row:
        return dict(row)
    wid = "ws_" + uuid.uuid4().hex[:16]
    con.execute("INSERT INTO workspaces (id, owner_id, name, created_at, digest, digest_sent_at, webhook_url, notify_min) "
                "VALUES (?,?,?,?,?,?,?,?)", (wid, user_id, "My workspace", _iso(_now()), "off", "", "", "high"))
    con.commit()
    return dict(con.execute("SELECT * FROM workspaces WHERE id=?", (wid,)).fetchone())


def workspace_by_id(con, wid: str) -> dict | None:
    row = con.execute("SELECT * FROM workspaces WHERE id=?", (wid,)).fetchone()
    return dict(row) if row else None


def all_workspaces(con) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT w.*, u.email AS owner_email FROM workspaces w JOIN users u ON u.id=w.owner_id")]


def validate_watch(kind: str, value: str) -> tuple[str, str] | str:
    """(kind, cleaned value) when valid, otherwise a plain-language reason."""
    kind = (kind or "").strip().lower() if isinstance(kind, str) else ""
    value = (value or "").strip().lower() if isinstance(value, str) else ""
    if kind == "domain" and _DOMAIN.match(value) and len(value) <= 253:
        return kind, value
    if kind == "email" and _WEMAIL.match(value) and len(value) <= 254:
        return kind, value
    if kind == "product" and _PRODUCT.match(value):
        return kind, value
    if kind not in ("domain", "email", "product"):
        return "kind must be domain, email or product"
    return f"That does not look like a valid {kind}."


def watch_list(con, wid: str) -> list[dict]:
    return [{"kind": r["kind"], "value": r["value"]} for r in con.execute(
        "SELECT kind, value FROM ws_watch WHERE workspace_id=? ORDER BY kind, value", (wid,))]


def watch_add(con, wid: str, kind: str, value: str) -> str | None:
    """None on success, otherwise the reason it was refused."""
    v = validate_watch(kind, value)
    if isinstance(v, str):
        return v
    existing = watch_list(con, wid)
    if {"kind": v[0], "value": v[1]} not in existing and len(existing) >= WORKSPACE_WATCH_MAX:
        return f"A workspace can watch at most {WORKSPACE_WATCH_MAX} things."
    con.execute(db._upsert("ws_watch", ["workspace_id", "kind", "value"], ["workspace_id", "kind", "value"]), (wid, v[0], v[1]))
    con.commit()
    return None


def watch_remove(con, wid: str, kind: str, value: str) -> None:
    con.execute("DELETE FROM ws_watch WHERE workspace_id=? AND kind=? AND value=?",
                (wid, (kind or "").strip().lower(), (value or "").strip().lower()))
    con.commit()


# ---------------- settings, webhook safety ----------------

def check_webhook_url(url: str) -> str | None:
    """None when it is safe to POST alerts to, otherwise why not. https only, no embedded credentials, and every address
    it resolves to must be a public one: an alert webhook must never be a way to reach the server's own network."""
    if not url:
        return None
    if not isinstance(url, str) or len(url) > 500:
        return "That address is too long."
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return "That does not look like a web address."
    if parts.scheme != "https" or not host:
        return "Use a full https:// address."
    if parts.username or parts.password:
        return "The address must not contain a username or password."
    if port not in (None, 443):
        return "Only the standard https port is allowed."
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return "That address could not be found."
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return "That address points to a private network, which is not allowed."
        except ValueError:
            return "That address could not be checked."
    return None


def set_settings(con, wid: str, digest: str | None = None, webhook_url: str | None = None, notify_min: str | None = None) -> str | None:
    if digest is not None and digest not in DIGEST_CHOICES:
        return "digest must be off, daily or weekly"
    if notify_min is not None and notify_min not in NOTIFY_CHOICES:
        return "notify_min must be low, medium, high or critical"
    if webhook_url is not None:
        why = check_webhook_url(webhook_url.strip())
        if why:
            return why
    ws = workspace_by_id(con, wid)
    if ws is None:
        return "workspace not found"
    con.execute("UPDATE workspaces SET digest=?, webhook_url=?, notify_min=? WHERE id=?",
                (digest if digest is not None else ws["digest"], webhook_url.strip() if webhook_url is not None else ws["webhook_url"],
                 notify_min if notify_min is not None else ws["notify_min"], wid))
    con.commit()
    return None


# ---------------- API keys ----------------

def create_api_key(con, wid: str, label: str) -> tuple[dict, str] | str:
    """(key record, the key itself, shown once) or a reason it was refused."""
    if len(api_keys(con, wid)) >= MAX_API_KEYS:
        return f"A workspace can have at most {MAX_API_KEYS} API keys. Revoke one first."
    key = "dlk_" + secrets.token_urlsafe(24)
    kid = "k_" + uuid.uuid4().hex[:12]
    label = " ".join((label or "").split())[:60] or "API key"
    con.execute("INSERT INTO api_keys (id, workspace_id, key_hash, label, created_at, last_used) VALUES (?,?,?,?,?,?)",
                (kid, wid, hash_secret(key), label, _iso(_now()), ""))
    con.commit()
    return {"id": kid, "label": label, "created_at": _iso(_now()), "last_used": ""}, key


def api_keys(con, wid: str) -> list[dict]:
    return [{"id": r["id"], "label": r["label"], "created_at": r["created_at"], "last_used": r["last_used"]} for r in con.execute(
        "SELECT id, label, created_at, last_used FROM api_keys WHERE workspace_id=? ORDER BY created_at", (wid,))]


def revoke_api_key(con, wid: str, kid: str) -> None:
    con.execute("DELETE FROM api_keys WHERE id=? AND workspace_id=?", (kid, wid))
    con.commit()


def workspace_for_api_key(con, key: str | None) -> dict | None:
    if not isinstance(key, str) or not key.startswith("dlk_") or len(key) > 100:
        return None
    row = con.execute("SELECT id, workspace_id FROM api_keys WHERE key_hash=?", (hash_secret(key),)).fetchone()
    if row is None:
        return None
    con.execute("UPDATE api_keys SET last_used=? WHERE id=?", (_iso(_now()), row["id"]))
    con.commit()
    return workspace_by_id(con, row["workspace_id"])


# ---------------- connectors (Slack, Discord, Teams) ----------------

CONNECTOR_KINDS = ("slack", "discord", "teams")


def check_connector_url(kind: str, url: str) -> str | None:
    """None when the address is a safe, public https address of the right service; otherwise why not."""
    if kind not in CONNECTOR_KINDS:
        return "kind must be slack, discord or teams"
    why = check_webhook_url(url)
    if why:
        return why
    parts = urlsplit(url)
    host, path = (parts.hostname or "").lower(), parts.path or ""
    if kind == "slack" and not (host == "hooks.slack.com" and path.startswith("/services/")):
        return "A Slack webhook starts with https://hooks.slack.com/services/."
    if kind == "discord" and not (host in ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")
                                  and path.startswith("/api/webhooks/")):
        return "A Discord webhook starts with https://discord.com/api/webhooks/."
    if kind == "teams" and not (host.endswith(".webhook.office.com") or host.endswith(".logic.azure.com")
                                or host.endswith(".powerplatform.com")):
        return "A Teams webhook is a webhook.office.com, logic.azure.com or powerplatform.com address."
    return None


def connectors(con, wid: str) -> list[dict]:
    return [{"kind": r["kind"], "url": r["url"], "min_severity": r["min_severity"] or "high", "created_at": r["created_at"]}
            for r in con.execute("SELECT kind, url, min_severity, created_at FROM ws_connectors WHERE workspace_id=? ORDER BY kind", (wid,))]


def set_connector(con, wid: str, kind: str, url: str, min_severity: str = "high") -> str | None:
    """Add or replace one connector. None on success, otherwise the reason it was refused."""
    kind = (kind or "").strip().lower()
    url = (url or "").strip()
    if min_severity not in NOTIFY_CHOICES:
        return "min_severity must be low, medium, high or critical"
    why = check_connector_url(kind, url)
    if why:
        return why
    con.execute("DELETE FROM ws_connectors WHERE workspace_id=? AND kind=?", (wid, kind))
    con.execute("INSERT INTO ws_connectors (workspace_id, kind, url, min_severity, created_at) VALUES (?,?,?,?,?)",
                (wid, kind, url, min_severity, _iso(_now())))
    con.commit()
    return None


def set_connector_level(con, wid: str, kind: str, min_severity: str) -> str | None:
    if min_severity not in NOTIFY_CHOICES:
        return "min_severity must be low, medium, high or critical"
    con.execute("UPDATE ws_connectors SET min_severity=? WHERE workspace_id=? AND kind=?", (min_severity, wid, kind))
    con.commit()
    return None


def remove_connector(con, wid: str, kind: str) -> None:
    con.execute("DELETE FROM ws_connectors WHERE workspace_id=? AND kind=?", (wid, (kind or "").strip().lower()))
    con.commit()
