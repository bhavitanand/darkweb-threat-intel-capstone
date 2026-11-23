"""Sending email: sign-in links and digests.

Two providers, chosen by what is configured (nothing else in the project needs to know which):

  Brevo HTTP API   BREVO_API_KEY  (free tier: 300 emails a day), sender from MAIL_FROM
  SMTP             SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD, sender from MAIL_FROM

`configured()` says whether either is set. Nothing is ever sent unless one is. Secrets stay in the environment and are
never logged. Subject and addresses are cleaned so a newline in them can never add an email header.
"""
from __future__ import annotations

import logging
import os
import smtplib
import time
from email.message import EmailMessage

log = logging.getLogger("darklens.mailer")


# One budget for the whole server, so a flood of sign-in requests for different addresses cannot use up the provider's
# daily quota (Brevo's free plan: 300 a day) and stop real sign-ins. MAIL_DAILY_LIMIT overrides; 0 turns the cap off.
_sent: list[float] = []


def _daily_limit() -> int:
    try:
        return int(os.environ.get("MAIL_DAILY_LIMIT", "250"))
    except ValueError:
        return 250


def _budget_left() -> bool:
    limit = _daily_limit()
    if limit <= 0:
        return True
    now = time.time()
    _sent[:] = [t for t in _sent if now - t < 86400]
    return len(_sent) < limit


class MailError(RuntimeError):
    """The message could not be sent (provider down, refused, or not configured)."""


def configured() -> bool:
    return bool(os.environ.get("BREVO_API_KEY") or os.environ.get("SMTP_HOST"))


def sender() -> str:
    return os.environ.get("MAIL_FROM") or os.environ.get("ALERT_EMAIL_FROM") or os.environ.get("SMTP_USER") or "darklens@localhost"


def _one_line(s: str, limit: int) -> str:
    return " ".join(str(s or "").split())[:limit]


def send(to: str, subject: str, body: str) -> None:
    """Send a plain-text email. Raises MailError on any failure; callers decide whether that matters."""
    to, subject = _one_line(to, 254), _one_line(subject, 150)
    if not configured():
        raise MailError("Email sending is not configured on this server.")
    if "@" not in to or any(c in to for c in " <>,;\"'"):
        raise MailError("That does not look like an email address.")
    if not _budget_left():
        raise MailError("Too many emails have been sent today. Try again later.")
    try:
        if os.environ.get("BREVO_API_KEY"):
            import requests

            r = requests.post("https://api.brevo.com/v3/smtp/email", timeout=15,
                              headers={"api-key": os.environ["BREVO_API_KEY"], "accept": "application/json"},
                              json={"sender": {"email": sender(), "name": "DarkLens"}, "to": [{"email": to}],
                                    "subject": subject, "textContent": body})
            if r.status_code >= 300:
                raise MailError(f"The email provider refused the message ({r.status_code}).")
            _sent.append(time.time())
            return
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, sender(), to
        msg.set_content(body)
        port = int(os.environ.get("SMTP_PORT", "587"))
        with smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=20) as s:
            if port != 25:
                s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
        _sent.append(time.time())
    except MailError:
        raise
    except Exception as e:  # noqa: BLE001 - provider and network errors vary; never leak details such as keys
        log.warning("email failed: %s", type(e).__name__)
        raise MailError("The email could not be sent right now.") from e
