"""Public text for labelling: security-news and tech headlines from RSS feeds, plus the Hacker News front page.

Only titles and short summaries are read, for private research use. Nothing here is committed or published.
Feeds are untrusted input, so XML is size-capped and anything declaring a DTD or entity is refused (that is how
"billion laughs" attacks work against the standard library parser).
"""
from __future__ import annotations

import hashlib
import html
import re
import xml.etree.ElementTree as ET

USER_AGENT = "DarkLens-research/0.2 (academic capstone; private labelling set)"
MAX_BYTES = 2_000_000

# (name, url, kind): "security" feeds supply the threat classes, "general" feeds supply ordinary text for the
# false-alarm measurement. All are public RSS.
FEEDS = [
    ("bleepingcomputer", "https://www.bleepingcomputer.com/feed/", "security"),
    ("thehackernews", "https://feeds.feedburner.com/TheHackersNews", "security"),
    ("krebsonsecurity", "https://krebsonsecurity.com/feed/", "security"),
    ("therecord", "https://therecord.media/feed", "security"),
    ("securityweek", "https://feeds.feedburner.com/securityweek", "security"),
    ("darkreading", "https://www.darkreading.com/rss.xml", "security"),
    ("securityaffairs", "https://securityaffairs.com/feed", "security"),
    ("helpnetsecurity", "https://www.helpnetsecurity.com/feed/", "security"),
    ("hackread", "https://hackread.com/feed/", "security"),
    ("theregister-security", "https://www.theregister.com/security/headlines.atom", "security"),
    ("cisa-advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "security"),
    ("talos", "https://blog.talosintelligence.com/rss/", "security"),
    ("welivesecurity", "https://www.welivesecurity.com/en/rss/feed/", "security"),
    ("securelist", "https://securelist.com/feed/", "security"),
    ("sophos", "https://news.sophos.com/en-us/feed/", "security"),
    ("schneier", "https://www.schneier.com/feed/atom/", "security"),
    ("sans-isc", "https://isc.sans.edu/rssfeed.xml", "security"),
    ("arstechnica", "https://feeds.arstechnica.com/arstechnica/index", "general"),
    ("bbc-technology", "https://feeds.bbci.co.uk/news/technology/rss.xml", "general"),
    ("bbc-business", "https://feeds.bbci.co.uk/news/business/rss.xml", "general"),
    ("bbc-science", "https://feeds.bbci.co.uk/news/science_and_environment/rss.xml", "general"),
]
HN_URL = "https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=100"

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def clean(text: str | None, limit: int = 400) -> str:
    """Strip markup, unescape entities, collapse whitespace and keep it short."""
    t = html.unescape(_TAG.sub(" ", text or ""))
    t = _WS.sub(" ", t).strip()
    return t if len(t) <= limit else t[: limit - 1].rsplit(" ", 1)[0] + "..."


def text_id(text: str) -> str:
    return hashlib.sha1(_WS.sub(" ", text.lower()).strip().encode("utf-8")).hexdigest()[:10]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_feed(xml, source: str, kind: str) -> list[dict]:
    """Parse RSS 2.0 or Atom into [{text, source, kind}]. Returns [] for anything unsafe or unreadable.

    Pass the raw BYTES from the network when you can: the XML declaration says how they are encoded (some feeds use
    Windows-1252), and decoding them as UTF-8 first turns every apostrophe into a replacement character."""
    data = xml.encode("utf-8") if isinstance(xml, str) else xml
    if len(data) > MAX_BYTES or re.search(rb"<!(DOCTYPE|ENTITY)", data, re.I):
        return []
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, LookupError):  # LookupError: the feed named an encoding Python does not know
        return []
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        fields = {_local(c.tag): (c.text or "") for c in el}
        title = clean(fields.get("title"), 200)
        summary = clean(fields.get("description") or fields.get("summary") or "", 300)
        if not title:
            continue
        text = title if not summary or summary.lower().startswith(title.lower()[:40]) else f"{title}. {summary}"
        out.append({"text": text, "source": source, "kind": kind})
    return out


def parse_hn(payload: dict) -> list[dict]:
    hits = payload.get("hits") if isinstance(payload, dict) else None
    return [{"text": clean(h.get("title"), 200), "source": "hackernews", "kind": "general"}
            for h in (hits or []) if isinstance(h, dict) and h.get("title")]


def fetch_all(get=None, feeds=None) -> tuple[list[dict], dict]:
    """Fetch every feed. One failing feed never stops the rest. Returns (items, {source: count or error})."""
    if get is None:
        import requests

        def get(url):  # noqa: E306
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
            r.raise_for_status()
            return r.content[:MAX_BYTES], r.headers.get("content-type", "")  # raw bytes: see parse_feed

    report: dict = {}
    items: list[dict] = []
    for name, url, kind in (feeds if feeds is not None else FEEDS):
        try:
            body, _ = get(url)
            got = parse_feed(body, name, kind)
            report[name] = len(got)
            items += got
        except Exception as e:  # noqa: BLE001
            report[name] = f"error: {type(e).__name__}"
    try:
        import json
        body, _ = get(HN_URL)
        got = parse_hn(json.loads(body))
        report["hackernews"] = len(got)
        items += got
    except Exception as e:  # noqa: BLE001
        report["hackernews"] = f"error: {type(e).__name__}"
    seen, unique = set(), []
    for it in items:
        tid = text_id(it["text"])
        if tid not in seen and len(it["text"]) >= 20:
            seen.add(tid)
            it["id"] = tid
            unique.append(it)
    return unique, report
