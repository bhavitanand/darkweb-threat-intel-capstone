"""Indicator-of-compromise extraction with validation (regex plus checksum / sanity checks)."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import OrderedDict

# Deliberately conservative: precision matters more than recall for alerting.
RE_URL = re.compile(r"\bhttps?://[^\s<>\"')]+", re.I)
RE_ONION = re.compile(r"\b[a-z2-7]{56}\.onion\b|\b[a-z2-7]{16}\.onion\b", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I)
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
RE_TRX = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")

# File extensions that look like TLDs but are not domains.
_FAKE_TLDS = {
    "exe", "dll", "zip", "rar", "txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "sql", "json",
    "png", "jpg", "jpeg", "gif", "py", "js", "html", "php", "bat", "ps1", "7z", "iso", "log", "db",
}

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def valid_base58check(addr: str) -> bool:
    """Real Base58Check validation so random 26-35 char strings are not reported as wallets."""
    raw = _b58decode(addr)
    if raw is None or len(raw) < 5:
        return False
    payload, check = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == check


def valid_btc(addr: str) -> bool:
    if addr.lower().startswith("bc1"):
        return bool(re.fullmatch(r"bc1[ac-hj-np-z02-9]{11,71}", addr.lower()))
    return valid_base58check(addr)


def valid_trx(addr: str) -> bool:
    raw = _b58decode(addr)
    return bool(raw) and len(raw) == 25 and raw[0] == 0x41 and valid_base58check(addr)


def _public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local)


def defang(text: str) -> str:
    """Refang common obfuscations: hxxp, [.] and (dot)."""
    t = text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("(dot)", ".")
    t = re.sub(r"\bhxxp", "http", t, flags=re.I)
    t = t.replace("[at]", "@").replace("(at)", "@")
    return t


def _uniq(xs):
    return list(OrderedDict.fromkeys(xs))


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Return validated IOCs found in `text`, grouped by type."""
    t = defang(text or "")
    out: dict[str, list[str]] = {}

    urls = _uniq(RE_URL.findall(t))
    onions = _uniq(x.lower() for x in RE_ONION.findall(t))
    emails = _uniq(x.lower() for x in RE_EMAIL.findall(t))
    ips = _uniq(x for x in RE_IPV4.findall(t) if _public_ip(x))
    sha256 = _uniq(x.lower() for x in RE_SHA256.findall(t))
    sha1 = _uniq(x.lower() for x in RE_SHA1.findall(t) if x.lower() not in {h[:40] for h in sha256})
    md5 = _uniq(x.lower() for x in RE_MD5.findall(t)
                if not any(x.lower() in h for h in sha256 + sha1))
    cves = _uniq(x.upper() for x in RE_CVE.findall(t))
    btc = _uniq(x for x in RE_BTC.findall(t) if valid_btc(x))
    eth = _uniq(x.lower() for x in RE_ETH.findall(t))
    xmr = _uniq(RE_XMR.findall(t))
    trx = _uniq(x for x in RE_TRX.findall(t) if valid_trx(x))

    # Domains: exclude ones that are only part of an email, url host already counted, onion, or fake TLD.
    email_domains = {e.split("@", 1)[1] for e in emails}
    domains = []
    for d in RE_DOMAIN.findall(t):
        dl = d.lower()
        tld = dl.rsplit(".", 1)[-1]
        if tld in _FAKE_TLDS or tld == "onion" or dl in email_domains:
            continue
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", dl):
            continue
        domains.append(dl)
    domains = _uniq(domains)

    for key, vals in [
        ("url", urls), ("onion", onions), ("email", emails), ("ipv4", ips), ("domain", domains),
        ("sha256", sha256), ("sha1", sha1), ("md5", md5), ("cve", cves),
        ("btc", btc), ("eth", eth), ("xmr", xmr), ("trx", trx),
    ]:
        if vals:
            out[key] = vals
    return out


def flatten(iocs: dict[str, list[str]]) -> list[tuple[str, str]]:
    return [(k, v) for k, vs in iocs.items() for v in vs]
