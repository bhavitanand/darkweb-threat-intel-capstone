"""Credential exposure checks.

Two safe building blocks:
  * Pwned Passwords range API (free, no key, k-anonymity): only the first 5 chars of the SHA-1 hash
    ever leave the machine. https://haveibeenpwned.com/API/v3
  * Local watchlist matching of domains/emails against emails found inside collected items.

Per-email breach search is a paid HIBP feature (hibp-api-key); it is optional and off by default.
"""
from __future__ import annotations

import hashlib
import re

RE_COMBO = re.compile(r"([\w.+-]+@[\w-]+\.[\w.]+):(\S{3,})")


def sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def range_query_parts(password: str) -> tuple[str, str]:
    h = sha1_upper(password)
    return h[:5], h[5:]


def parse_range_response(body: str, suffix: str) -> int:
    """Return the pwn count for `suffix` from a range response (SUFFIX:COUNT lines). Padded rows have count 0."""
    for line in body.splitlines():
        s, _, c = line.strip().partition(":")
        if s.upper() == suffix.upper():
            return int(c or 0)
    return 0


def pwned_count(password: str, offline_table: dict[str, int] | None = None) -> int:
    """How many times a password appears in known breaches. Offline mode uses a small local table."""
    if offline_table is not None:
        return offline_table.get(sha1_upper(password), 0)
    import requests

    prefix, suffix = range_query_parts(password)
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                     headers={"Add-Padding": "true", "User-Agent": "DarkLens-research/0.1"}, timeout=15)
    r.raise_for_status()
    return parse_range_response(r.text, suffix)


def parse_combolist(text: str) -> list[tuple[str, str]]:
    return RE_COMBO.findall(text or "")


def credential_exposure(text: str, watch_domains: list[str]) -> list[dict]:
    """Find email:password pairs for watched domains. Passwords are NEVER returned, only masked and hashed."""
    hits = []
    watch = {d.lower().lstrip("@") for d in watch_domains}
    for email, pw in parse_combolist(text):
        dom = email.split("@", 1)[1].lower()
        if dom in watch or any(dom.endswith("." + w) for w in watch):
            hits.append({"email": email.lower(), "password_masked": pw[0] + "*" * (len(pw) - 1),
                         "password_sha1_prefix": sha1_upper(pw)[:5], "length": len(pw)})
    return hits
