"""Export alerts as CSV (for spreadsheets) and as a STIX 2.1 bundle (for other threat-intelligence tools).

Both take the same list of alert dicts the API returns, so they are pure functions and easy to test.
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone

_NS = uuid.UUID("5f4c2f0e-8d3a-4f1b-9c53-7d1a0b6e2a11")  # fixed namespace: the same input always gives the same ids
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")

CSV_COLUMNS = ["id", "severity", "score", "category", "confidence", "title", "source", "actor", "org", "country",
               "seen_at", "url", "demo", "indicators", "top_reasons"]


def _safe_cell(v) -> str:
    """Spreadsheets run text that starts with = + - @ as a formula. Alert text comes from the internet, so neutralise it."""
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA_STARTS) else s


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
