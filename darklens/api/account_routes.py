"""Sign-in, the private workspace, API keys, the digest and the alert webhook.

Sign-in is by emailed single-use link (see darklens/accounts.py). A browser keeps the session token it is given and
sends it as `Authorization: Bearer <token>`; a program uses an API key in `X-API-Key` (read-only, workspace alerts only).
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from .. import accounts, mailer, workspace

log = logging.getLogger("darklens.account")


class EmailIn(BaseModel):
    email: str = Field(max_length=320)


class TokenIn(BaseModel):
    token: str = Field(max_length=300)


class WatchIn(BaseModel):
    kind: str = Field(max_length=10)
    value: str = Field(max_length=200)


class SettingsIn(BaseModel):
    digest: str | None = Field(default=None, max_length=10)
    webhook_url: str | None = Field(default=None, max_length=500)
    notify_min: str | None = Field(default=None, max_length=10)


class KeyIn(BaseModel):
    label: str = Field(default="", max_length=80)


def build_router(con, lock) -> APIRouter:
    """`con` returns the store connection; `lock` serialises writes (the same lock the rest of the API uses)."""
    r = APIRouter()

    def bearer(authorization: str | None) -> str | None:
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return None

    def current(authorization: str | None) -> tuple[dict, dict]:
        user = accounts.session_user(con(), bearer(authorization))
        if user is None:
            raise HTTPException(401, "Please sign in.")
        return user, accounts.ensure_workspace(con(), user["id"])

    def view(ws: dict) -> dict:
        c = con()
        return {"id": ws["id"], "name": ws["name"], "digest": ws["digest"] or "off", "notify_min": ws["notify_min"] or "high",
                "webhook_url": ws["webhook_url"] or "", "entries": accounts.watch_list(c, ws["id"]),
                "api_keys": accounts.api_keys(c, ws["id"]), "email_ready": mailer.configured(),
                "limits": {"entries": accounts.WORKSPACE_WATCH_MAX, "api_keys": accounts.MAX_API_KEYS}}

    @r.post("/api/auth/request")
    def request_link(body: EmailIn):
        """Email a single-use sign-in link. The answer is the same whether or not the address has an account."""
        email = accounts.normalise_email(body.email)
        if email is None:
            raise HTTPException(400, "That does not look like an email address.")
        dev = os.environ.get("AUTH_DEV_LINKS") == "1"
        if not mailer.configured() and not dev:
            raise HTTPException(503, "Sign-in by email is not set up on this server yet.")
        with lock:
            token = accounts.request_login(con(), email)
        out = {"ok": True, "message": "If that address is valid, a sign-in link is on its way. It works once, for 15 minutes."}
        if token is None:
            return out  # asked too often: same answer, nothing sent
        base = os.environ.get("PUBLIC_APP_URL", "").rstrip("/")
        link = f"{base}/#/signin?token={token}"
        if mailer.configured():
            try:
                mailer.send(email, "Your DarkLens sign-in link",
                            f"Follow this link to sign in to DarkLens. It works once and expires in {accounts.LOGIN_TTL_MINUTES} minutes.\n\n"
                            f"{link}\n\nIf you did not ask for this, ignore this email: nothing happens unless the link is opened.")
            except mailer.MailError as e:
                raise HTTPException(503, str(e)) from e
        else:
            out["dev_link"] = link  # AUTH_DEV_LINKS=1: for local development and demos, never set this in production
        return out

    @r.post("/api/auth/verify")
    def verify(body: TokenIn):
        with lock:
            got = accounts.verify_login(con(), body.token)
        if got is None:
            raise HTTPException(400, "That sign-in link is not valid any more. Ask for a new one.")
        user, session = got
        return {"token": session, "email": user["email"], "expires_in_days": accounts.SESSION_DAYS}

    @r.post("/api/auth/logout")
    def logout(authorization: str | None = Header(default=None)):
        with lock:
            accounts.end_session(con(), bearer(authorization))
        return {"ok": True}

    @r.get("/api/me")
    def me(authorization: str | None = Header(default=None)):
        user, ws = current(authorization)
        return {"email": user["email"], "workspace": view(ws)}

    @r.delete("/api/account")
    def delete_account(authorization: str | None = Header(default=None)):
        user, _ = current(authorization)
        with lock:
            accounts.delete_account(con(), user["id"])
        return {"ok": True}

    @r.get("/api/workspace")
    def get_workspace(authorization: str | None = Header(default=None)):
        return view(current(authorization)[1])

    @r.post("/api/workspace/watch")
    def add_watch(body: WatchIn, authorization: str | None = Header(default=None)):
        _, ws = current(authorization)
        with lock:
            why = accounts.watch_add(con(), ws["id"], body.kind, body.value)
        if why:
            raise HTTPException(400, why)
        return view(accounts.workspace_by_id(con(), ws["id"]))

    @r.delete("/api/workspace/watch")
    def remove_watch(kind: str, value: str, authorization: str | None = Header(default=None)):
        _, ws = current(authorization)
        with lock:
            accounts.watch_remove(con(), ws["id"], kind, value)
        return view(accounts.workspace_by_id(con(), ws["id"]))

    @r.get("/api/workspace/alerts")
    def workspace_alerts(limit: int = 100, authorization: str | None = Header(default=None),
                         x_api_key: str | None = Header(default=None)):
        """Alerts about this workspace's own watchlist. A signed-in browser or a read-only API key can ask."""
        ws = accounts.workspace_for_api_key(con(), x_api_key) if x_api_key else None
        if ws is None:
            if x_api_key:
                raise HTTPException(401, "That API key is not valid.")
            ws = current(authorization)[1]
        return workspace.personal_alerts(con(), ws["id"], min(max(limit, 1), 300))

    @r.put("/api/workspace/settings")
    def settings(body: SettingsIn, authorization: str | None = Header(default=None)):
        _, ws = current(authorization)
        with lock:
            why = accounts.set_settings(con(), ws["id"], body.digest, body.webhook_url, body.notify_min)
        if why:
            raise HTTPException(400, why)
        return view(accounts.workspace_by_id(con(), ws["id"]))

    @r.post("/api/workspace/keys")
    def new_key(body: KeyIn, authorization: str | None = Header(default=None)):
        _, ws = current(authorization)
        with lock:
            got = accounts.create_api_key(con(), ws["id"], body.label)
        if isinstance(got, str):
            raise HTTPException(400, got)
        record, key = got
        return {**record, "key": key, "note": "Copy this key now. It is shown once and cannot be recovered."}

    @r.delete("/api/workspace/keys/{key_id}")
    def revoke_key(key_id: str, authorization: str | None = Header(default=None)):
        _, ws = current(authorization)
        with lock:
            accounts.revoke_api_key(con(), ws["id"], key_id[:40])
        return view(accounts.workspace_by_id(con(), ws["id"]))

    @r.get("/api/workspace/digest/preview")
    def digest_preview(authorization: str | None = Header(default=None)):
        """What the next digest would say, without sending or marking anything as sent."""
        _, ws = current(authorization)
        subject, body, ids = workspace.build_digest(con(), ws["id"])
        return {"count": len(ids), "subject": subject, "body": body}

    @r.post("/api/workspace/digest/send")
    def digest_send(authorization: str | None = Header(default=None)):
        user, ws = current(authorization)
        if not mailer.configured():
            raise HTTPException(503, "Email sending is not set up on this server yet.")
        with lock:
            try:
                n = workspace.send_digest(con(), ws, user["email"])
            except mailer.MailError as e:
                raise HTTPException(503, str(e)) from e
        return {"sent": n > 0, "count": n}

    @r.post("/api/workspace/webhook/test")
    def webhook_test(authorization: str | None = Header(default=None)):
        _, ws = current(authorization)
        if not ws["webhook_url"]:
            raise HTTPException(400, "Add a webhook address first.")
        try:
            workspace.post_webhook(ws["webhook_url"], "DarkLens test message: your alert webhook works.")
        except Exception as e:  # noqa: BLE001
            raise HTTPException(400, f"The test message could not be delivered ({type(e).__name__}).") from e
        return {"ok": True}

    return r
