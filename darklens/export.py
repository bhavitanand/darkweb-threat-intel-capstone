"""Export alerts as CSV (for spreadsheets) and as a STIX 2.1 bundle (for other threat-intelligence tools).

Both take the same list of alert dicts the API returns, so they are pure functions and easy to test.
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone

_NS = uuid.UUID("5f4c2f0e-8d3a-4f1b-9c53-7d1a0b6e2a11")  # fixed namespace: the same input always gives the same ids
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r", "\n", " ", "​", "﻿")  # incl. hidden leading characters

CSV_COLUMNS = ["id", "severity", "score", "category", "confidence", "title", "source", "actor", "org", "country",
               "seen_at", "url", "demo", "indicators", "top_reasons"]


def _safe_cell(v) -> str:
    """Spreadsheets run text that starts with = + - @ as a formula. Alert text comes from the internet, so neutralise it."""
    s = "" if v is None else str(v)
    # Also catch a formula hidden behind leading spaces ("  =1+1"): look at the first visible character.
    return "'" + s if s.startswith(_FORMULA_STARTS) or s.lstrip(" ").startswith(_FORMULA_STARTS[:4]) else s


def to_csv(alerts: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for a in alerts:
        iocs = "; ".join(f"{t}:{v}" for t, vals in (a.get("iocs") or {}).items() for v in vals)
        reasons = "; ".join(s["name"] for s in sorted(a.get("signals") or [], key=lambda s: -s["score"])[:3])
        row = [a["item_id"], a["severity"], a["score"], a["category"], round(a["confidence"], 3), a.get("title"),
               a.get("source"), a.get("actor"), a.get("org"), a.get("country"), a.get("seen_at"), a.get("url"),
               "yes" if a.get("demo") else "no", iocs, reasons]
        w.writerow([_safe_cell(c) for c in row])
    return buf.getvalue()


# ---------------- STIX 2.1 ----------------

def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + '|' + key)}"


def _ts(value: str | None, fallback: str) -> str:
    """STIX timestamps are RFC 3339 with milliseconds and a Z. Accepts '2026-11-15' and '2026-11-15T10:00:00Z'."""
    if value:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                return datetime.strptime(value[:20] if "T" in value else value[:10], fmt).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except ValueError:
                continue
    return fallback


def _q(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


_PATTERNS = {
    "ipv4": "[ipv4-addr:value = '{}']",
    "domain": "[domain-name:value = '{}']",
    "onion": "[domain-name:value = '{}']",
    "url": "[url:value = '{}']",
    "email": "[email-addr:value = '{}']",
    "sha256": "[file:hashes.'SHA-256' = '{}']",
    "sha1": "[file:hashes.'SHA-1' = '{}']",
    "md5": "[file:hashes.MD5 = '{}']",
}
_WALLETS = ("btc", "eth", "xmr", "trx")


def to_stix(alerts: list[dict], now: datetime | None = None) -> dict:
    """A STIX 2.1 bundle: one identity, one report per alert, indicators for network/file indicators, and
    vulnerabilities for CVEs. Crypto wallets have no standard STIX object, so they are carried in a custom
    property (x_darklens_wallets) on the report."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = _sid("identity", "darklens")
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": stamp, "modified": stamp,
        "name": "DarkLens", "identity_class": "system",
    }]
    seen: dict[str, dict] = {}

    def indicator(t: str, v: str, valid_from: str) -> str | None:
        pat = _PATTERNS.get(t)
        if not pat:
            return None
        oid = _sid("indicator", f"{t}|{v}")
        if oid not in seen:
            seen[oid] = {
                "type": "indicator", "spec_version": "2.1", "id": oid, "created": stamp, "modified": stamp,
                "created_by_ref": identity_id, "name": f"{t}: {v}"[:120], "indicator_types": ["malicious-activity"],
                "pattern": pat.format(_q(v)), "pattern_type": "stix", "valid_from": valid_from,
            }
        return oid

    def vulnerability(cve: str) -> str:
        oid = _sid("vulnerability", cve)
        if oid not in seen:
            seen[oid] = {
                "type": "vulnerability", "spec_version": "2.1", "id": oid, "created": stamp, "modified": stamp,
                "created_by_ref": identity_id, "name": cve,
                "external_references": [{"source_name": "cve", "external_id": cve}],
            }
        return oid

    for a in alerts:
        created = _ts(a.get("created_at"), stamp)
        refs: list[str] = []
        wallets: list[str] = []
        for t, vals in (a.get("iocs") or {}).items():
            for v in vals:
                if t == "cve":
                    refs.append(vulnerability(v))
                elif t in _WALLETS:
                    wallets.append(f"{t}:{v}")
                else:
                    oid = indicator(t, v, _ts(a.get("seen_at"), created))
                    if oid:
                        refs.append(oid)
        top = "; ".join(f"{s['name']} ({s['score']})" for s in sorted(a.get("signals") or [], key=lambda s: -s["score"])[:3])
        report = {
            "type": "report", "spec_version": "2.1", "id": _sid("report", a["item_id"]), "created": created,
            "modified": created, "created_by_ref": identity_id, "name": (a.get("title") or "Untitled alert")[:200],
            "description": f"Category: {a['category']}. Score {a['score']}/100 ({a['severity']}). Top signals: {top or 'none'}.",
            "report_types": ["threat-report"], "published": created,
            "object_refs": refs or [identity_id], "confidence": max(0, min(100, int(a["score"]))),
            "labels": [a["category"], a["severity"]] + (["demo-data"] if a.get("demo") else []),
        }
        if wallets:
            report["x_darklens_wallets"] = wallets
        if a.get("url"):
            report["external_references"] = [{"source_name": a.get("source") or "source", "url": a["url"]}]
        objects.append(report)
    objects += list(seen.values())
    return {"type": "bundle", "id": _sid("bundle", stamp + str(len(alerts))), "objects": objects}


# ---------------- MISP ----------------

_MISP_TYPES = {
    "ipv4": "ip-dst", "domain": "domain", "onion": "domain", "url": "url", "email": "email-src",
    "sha256": "sha256", "sha1": "sha1", "md5": "md5", "cve": "vulnerability", "btc": "btc", "xmr": "xmr",
}
_MISP_THREAT = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}


def to_misp(alerts: list[dict]) -> dict:
    """MISP event JSON (the format MISP's "import feed" and its API accept): one event per alert, with one
    attribute per indicator. Wallet types MISP has no type for (eth, trx) are left out."""
    events = []
    for a in alerts:
        attrs, seen = [], set()
        for t, vals in (a.get("iocs") or {}).items():
            mt = _MISP_TYPES.get(t)
            if not mt:
                continue
            for v in vals:
                if (mt, v) in seen:
                    continue
                seen.add((mt, v))
                attrs.append({"type": mt, "category": "Network activity" if mt != "vulnerability" else "External analysis",
                              "value": v, "to_ids": mt not in ("vulnerability",), "comment": "DarkLens"})
        date = (a.get("seen_at") or a.get("created_at") or "")[:10]
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events.append({"Event": {
            "uuid": str(uuid.uuid5(_NS, "misp|" + str(a["item_id"]))), "info": (a.get("title") or "Untitled alert")[:200],
            "date": date, "threat_level_id": _MISP_THREAT.get(a.get("severity"), "3"), "analysis": "1", "published": False,
            "Tag": [{"name": f"darklens:category=\"{a['category']}\""}, {"name": f"darklens:severity=\"{a['severity']}\""}]
                   + ([{"name": "darklens:demo-data"}] if a.get("demo") else []),
            "Attribute": attrs,
        }})
    return {"response": events}


# ---------------- TAXII 2.1 (read only) ----------------

TAXII_COLLECTION_ID = str(uuid.uuid5(_NS, "taxii|alerts"))
TAXII_TYPE = "application/taxii+json;version=2.1"


def taxii_discovery(base: str) -> dict:
    return {"title": "DarkLens", "description": "Read-only threat intelligence from public sources.",
            "default": f"{base}/taxii2/root/", "api_roots": [f"{base}/taxii2/root/"]}


def taxii_root() -> dict:
    return {"title": "DarkLens", "versions": [TAXII_TYPE], "max_content_length": 10_000_000}


def taxii_collection() -> dict:
    return {"id": TAXII_COLLECTION_ID, "title": "DarkLens alerts", "can_read": True, "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
            "description": "STIX 2.1 reports, indicators and vulnerabilities. Sources that forbid redistribution are left out."}


def taxii_objects(alerts: list[dict], limit: int = 500, offset: int = 0, types: set[str] | None = None) -> dict:
    objs = to_stix(alerts)["objects"]
    if types:
        objs = [o for o in objs if o["type"] in types]
    page = objs[offset:offset + limit]
    env: dict = {"more": offset + limit < len(objs), "objects": page}
    if env["more"]:
        env["next"] = str(offset + limit)
    return env
