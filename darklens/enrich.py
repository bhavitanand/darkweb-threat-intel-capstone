"""Look up one indicator with outside reputation services, for the providers whose free key is set.

OTX (`OTX_API_KEY`), VirusTotal (`VIRUSTOTAL_API_KEY`) and GreyNoise (`GREYNOISE_API_KEY`). Each is optional: with no key
the provider is simply absent. Values are validated strictly before they go into a URL (so an indicator can never change
which address is called), answers are cached in memory, one failing provider never hides the others, and only a short
fixed summary is returned, never the raw reply. Free tiers are small (VirusTotal: 4 requests a minute), so this runs
only when someone asks, never in bulk.
"""
from __future__ import annotations

import os
import re
import time
from urllib.parse import quote

TTL = 6 * 3600
CACHE_MAX = 500
TIMEOUT = 8

_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_HASH = {"md5": re.compile(r"^[a-f0-9]{32}$"), "sha1": re.compile(r"^[a-f0-9]{40}$"), "sha256": re.compile(r"^[a-f0-9]{64}$")}
SUPPORTED = ("ipv4", "domain", "md5", "sha1", "sha256")

_cache: dict[tuple, tuple[float, dict]] = {}
# All visitors share one budget per provider: the free quotas are small (VirusTotal: 4 a minute and 500 a day) and must not be
# burnt by one person. Kept a little under each published limit so we are never the one that gets blocked.
LIMITS = {"virustotal": (4, 400), "otx": (30, 2000), "greynoise": (10, 40)}  # (per minute, per day)
_calls: dict[str, list[float]] = {}
MAX_CALLS_PER_MIN = 12  # kept for tests that fill the budget generically


def normalise(kind: str, value: str) -> str | None:
    """The cleaned indicator, or None when it is not a valid one of that kind."""
    v = (value or "").strip().lower().rstrip(".")
    if kind == "ipv4" and _IPV4.match(v):
        return v
    if kind == "domain" and _DOMAIN.match(v):
        return v
    if kind in _HASH and _HASH[kind].match(v):
        return v
    return None


def providers() -> list[str]:
    return [n for n, env in (("otx", "OTX_API_KEY"), ("virustotal", "VIRUSTOTAL_API_KEY"), ("greynoise", "GREYNOISE_API_KEY"))
            if os.getenv(env, "").strip()]


def _get(url: str, headers: dict) -> dict:
    import requests

    r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, dict) else {}


def _int(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def _otx(kind: str, v: str) -> dict:
    section = {"ipv4": "IPv4", "domain": "domain"}.get(kind, "file")
    d = _get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(v, safe='')}/general",
             {"X-OTX-API-KEY": os.environ["OTX_API_KEY"].strip()})
    n = _int((d.get("pulse_info") or {}).get("count") if isinstance(d.get("pulse_info"), dict) else 0)
    return {"summary": f"In {n} threat report{'s' if n != 1 else ''} on AlienVault OTX." if n else "Not in any OTX threat report.",
            "flagged": n > 0, "link": f"https://otx.alienvault.com/indicator/{section.lower() if section != 'IPv4' else 'ip'}/{quote(v, safe='')}"}


def _vt(kind: str, v: str) -> dict:
    path = {"ipv4": "ip_addresses", "domain": "domains"}.get(kind, "files")
    d = _get(f"https://www.virustotal.com/api/v3/{path}/{quote(v, safe='')}", {"x-apikey": os.environ["VIRUSTOTAL_API_KEY"].strip()})
    attrs = (d.get("data") or {}).get("attributes") if isinstance(d.get("data"), dict) else None
    stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
    if not isinstance(stats, dict):
        return {"summary": "Not seen by VirusTotal.", "flagged": False, "link": ""}
    bad, total = _int(stats.get("malicious")) + _int(stats.get("suspicious")), sum(_int(x) for x in stats.values())
    gui = {"ipv4": "ip-address", "domain": "domain"}.get(kind, "file")
    return {"summary": f"{bad} of {total} security engines flag it on VirusTotal.", "flagged": bad > 0,
            "link": f"https://www.virustotal.com/gui/{gui}/{quote(v, safe='')}"}


def _gn(kind: str, v: str) -> dict:
    if kind != "ipv4":
        return {}
    d = _get(f"https://api.greynoise.io/v3/community/{quote(v, safe='')}", {"key": os.environ["GREYNOISE_API_KEY"].strip()})
    cls = d.get("classification") if isinstance(d.get("classification"), str) else ""
    if not d.get("noise") and not d.get("riot"):
        return {"summary": "Not seen scanning the internet (GreyNoise).", "flagged": False, "link": f"https://viz.greynoise.io/ip/{v}"}
    what = "a known harmless service" if d.get("riot") else f"internet-wide scanning ({cls or 'unclassified'})"
    return {"summary": f"GreyNoise sees it as {what}.", "flagged": cls == "malicious", "link": f"https://viz.greynoise.io/ip/{v}"}


_LOOKUPS = {"otx": _otx, "virustotal": _vt, "greynoise": _gn}


def _take(name: str) -> bool:
    """Spend one call from this provider's minute and day budget; False when either is used up."""
    per_min, per_day = LIMITS[name]
    now = time.time()
    log = [t for t in _calls.get(name, []) if now - t < 86400]
    if len(log) >= per_day or sum(1 for t in log if now - t < 60) >= per_min:
        _calls[name] = log
        return False
    log.append(now)
    _calls[name] = log
    return True


def lookup(kind: str, value: str) -> dict:
    """{"indicator", "kind", "results": {provider: {summary, flagged, link} | {error}}, "providers": [...]}. Raises ValueError on a bad indicator."""
    v = normalise(kind, value)
    if v is None:
        raise ValueError("That is not a valid indicator of that type.")
    active = providers()
    results: dict[str, dict] = {}
    for name in active:
        key = (name, kind, v)
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < TTL:
            results[name] = hit[1]
            continue
        if not _take(name):
            results[name] = {"error": "Lookups are busy, try again in a minute."}
            continue
        try:
            out = _LOOKUPS[name](kind, v)
        except Exception as e:  # noqa: BLE001  a provider being down or out of quota must not hide the others
            status = getattr(getattr(e, "response", None), "status_code", None)
            out = {"error": "Rate limit reached, try again in a minute." if status == 429 else "That service did not answer."}
            results[name] = out
            continue
        if not out:
            continue
        if len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[key] = (time.time(), out)
        results[name] = out
    return {"indicator": v, "kind": kind, "results": results, "providers": active}
