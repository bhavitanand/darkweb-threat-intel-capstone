"""Allowlisted, read-only Tor crawler.

Safety rules enforced IN CODE (not just in docs):
  * refuses any URL whose host is not in allowlist.yaml
  * GET only, text only; no login, no forms, no file downloads
  * stores a short snippet (max 600 chars), never the full page
  * global rate limit and a kill switch file (create `STOP_CRAWL` to halt immediately)
  * dry-run by default: nothing touches the network unless `live=True`

Run live only from a disposable VM/container with a Tor daemon (SOCKS 127.0.0.1:9050), never from a
personal machine. See SECURITY.md.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..models import Item

ALLOWLIST = Path(__file__).with_name("allowlist.yaml")
KILL_SWITCH = Path("STOP_CRAWL")
SNIPPET_MAX = 600
MIN_DELAY_SECONDS = 8
SOCKS = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}


class CrawlRefused(Exception):
    pass


def load_allowlist(path: Path = ALLOWLIST) -> set[str]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return {h.lower() for h in data.get("hosts", [])}


def check_allowed(url: str, allow: set[str]) -> str:
    host = (urlparse(url).hostname or "").lower()
    if KILL_SWITCH.exists():
        raise CrawlRefused("kill switch present")
    if urlparse(url).scheme not in ("http", "https"):
        raise CrawlRefused("scheme not allowed")
    if host not in allow:
        raise CrawlRefused(f"host not in allowlist: {host or url}")
    return host


def html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|noscript).*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def snippet(text: str) -> str:
    return text[:SNIPPET_MAX]


def crawl(urls: list[str], live: bool = False, allow: set[str] | None = None) -> list[Item]:
    allow = allow if allow is not None else load_allowlist()
    items: list[Item] = []
    for i, url in enumerate(urls):
        check_allowed(url, allow)  # raises before any network access
        if not live:
            continue  # dry run: validated only
        import requests

        if i:
            time.sleep(MIN_DELAY_SECONDS)
        r = requests.get(url, proxies=SOCKS, timeout=60, headers={"User-Agent": "Mozilla/5.0 (research)"})
        ctype = r.headers.get("content-type", "")
        if "text" not in ctype and "html" not in ctype:
            continue  # never store binaries or downloads
        items.append(Item(source="tor:allowlisted", kind="page", title=url, url=url,
                          text=snippet(html_to_text(r.text))))
    return items
