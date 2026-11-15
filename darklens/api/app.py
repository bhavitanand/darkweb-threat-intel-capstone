"""FastAPI backend plus the single-page dashboard. Run: uvicorn darklens.api.app:app --reload"""
from __future__ import annotations

import json
import threading
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from .. import __version__, pipeline
from ..evidence import build_pack
from ..graph import entities
from ..models import Item
from ..nlp.classifier import evaluate, get_classifier
from ..store import db

DASH = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
app = FastAPI(title="DarkLens", version=__version__)
_lock = threading.Lock()


def con():
    """One short-lived SQLite connection per call, so concurrent requests never share a cursor."""
    return db.connect()


@app.on_event("startup")
def seed():
    with _lock:
        c = db.connect()
        if c.execute("SELECT COUNT(*) c FROM items").fetchone()["c"] == 0:
            pipeline.run(offline=True, con=c)  # first start: load the offline demo data


class WatchIn(BaseModel):
    kind: str  # "domain" | "email"
    value: str


class AnalyseIn(BaseModel):
    text: str
    title: str = ""


def _alert_row(r) -> dict:
    d = dict(r)
    d["signals"] = json.loads(d["signals"])
    d["probs"] = json.loads(d["probs"])
    return d


def _rows(where: str = "", args: tuple = ()):
    q = ("SELECT a.*, i.source, i.kind, i.title, i.text, i.url, i.seen_at, i.actor, i.org, i.country "
         "FROM alerts a JOIN items i ON i.id=a.item_id " + where + " ORDER BY a.score DESC")
    return [_alert_row(r) for r in con().execute(q, args)]


def _iocs_for(item_id: str) -> dict:
    out: dict = {}
    for r in con().execute("SELECT type, value FROM iocs WHERE item_id=?", (item_id,)):
        out.setdefault(r["type"], []).append(r["value"])
    return out


@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse(DASH)


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.get("/api/stats")
def stats():
    rows = _rows()
    sev = Counter(r["severity"] for r in rows)
    cat = Counter(r["category"] for r in rows)
    ioc_counts = Counter(r["type"] for r in con().execute("SELECT type FROM iocs"))
    return {"alerts": len(rows), "items": con().execute("SELECT COUNT(*) c FROM items").fetchone()["c"],
            "by_severity": dict(sev), "by_category": dict(cat), "ioc_types": dict(ioc_counts),
            "attribution": "Source: Ransomware.live (victim claims). Demo data is synthetic."}


@app.get("/api/alerts")
def alerts(severity: str | None = None, category: str | None = None, q: str | None = None):
    rows = _rows()
    if severity:
        rows = [r for r in rows if r["severity"] == severity]
    if category:
        rows = [r for r in rows if r["category"] == category]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r["title"] + " " + r["text"]).lower()]
    for r in rows:
        r["iocs"] = _iocs_for(r["item_id"])
    return rows


@app.get("/api/alerts/{item_id}")
def alert(item_id: str):
    rows = _rows("WHERE a.item_id=?", (item_id,))
    if not rows:
        raise HTTPException(404, "alert not found")
    r = rows[0]
    r["iocs"] = _iocs_for(item_id)
    return r


@app.get("/api/alerts/{item_id}/evidence", response_class=HTMLResponse)
def evidence(item_id: str):
    page, _ = build_pack(alert(item_id))
    return HTMLResponse(page)


@app.get("/api/graph")
def graph():
    rows = _rows()
    for r in rows:
        r["id"] = r["item_id"]
        r["iocs"] = _iocs_for(r["item_id"])
    g = entities.build_graph(rows)
    return {"graph": entities.to_json(g), "linked_actors": entities.linked_actors(g)}


@app.get("/api/watchlist")
def watchlist():
    return [{"kind": k, "value": v} for k, v in db.watch_all(con())]


@app.post("/api/watchlist")
def watch_add(w: WatchIn):
    if w.kind not in ("domain", "email"):
        raise HTTPException(400, "kind must be domain or email")
    with _lock:
        c = con()
        db.watch_add(c, w.kind, w.value)
        pipeline.run(offline=True, con=c)  # re-score everything against the new watchlist
    return watchlist()


@app.post("/api/ingest")
def ingest(offline: bool = True):
    with _lock:
        return pipeline.run(offline=offline, con=con())


@app.post("/api/analyse")
def analyse(body: AnalyseIn):
    """Analyse any pasted text. Nothing is stored."""
    wl = db.watch_all(con())
    a = pipeline.analyse(Item(source="manual", kind="post", title=body.title, text=body.text),
                         [v for k, v in wl if k == "domain"], [v for k, v in wl if k == "email"], get_classifier())
    return {"category": a.category, "confidence": round(a.confidence, 3), "score": a.score, "severity": a.severity,
            "signals": [s.to_dict() for s in a.signals], "iocs": a.iocs, "probs": a.probs,
            "exposures": a.exposures}


@app.get("/api/eval")
def eval_metrics():
    r = evaluate(get_classifier())
    return {k: v for k, v in r.items() if k != "report_hybrid"} | {
        "note": "Macro-F1 on held-out synthetic templates. See README Honest limitations."}
