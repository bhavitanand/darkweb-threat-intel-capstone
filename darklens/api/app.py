"""FastAPI backend plus the original single-page dashboard. Run: uvicorn darklens.api.app:app --reload"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .. import __version__, export, ingest, notify, pipeline
from ..evidence import build_pack
from ..graph import entities
from ..mitre import techniques
from ..models import Item, now_iso
from ..nlp.classifier import evaluate, get_classifier
from ..nlp.corpus import CATEGORIES
from ..store import db
from .ratelimit import RateLimitMiddleware

DASH = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
app = FastAPI(title="DarkLens", version=__version__)
_lock = threading.Lock()
LABELS = set(CATEGORIES) | {"ioc_feed"}

_DOMAIN = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


# Order matters: middleware added last is outermost. CORS goes last so even a 429 carries CORS headers.
app.add_middleware(RateLimitMiddleware, read_per_min=_int_env("RATE_LIMIT_PER_MIN", 120),
                   write_per_min=_int_env("RATE_LIMIT_WRITE_PER_MIN", 20),
                   trust_proxy=os.getenv("TRUST_PROXY") == "1")

# CORS: the React frontend is served from a different origin (Vercel). Comma-separated exact origins in
# ALLOWED_ORIGINS (for example https://darklens.vercel.app). Unset means same-origin only, which is what the
# built-in dashboard and local development (Vite proxies /api) need.
_ORIGINS = [o.strip().rstrip("/") for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=_ORIGINS, allow_methods=["GET", "HEAD", "POST", "OPTIONS"],
                       allow_headers=["Content-Type", "X-Ingest-Token"], max_age=600)


def con():
    """SQLite: a short-lived connection per call. Postgres: the shared, reconnecting connection."""
    return db.connect()


@app.on_event("startup")
def seed():
    with _lock:
        c = db.connect()
        if c.execute("SELECT COUNT(*) c FROM items").fetchone()["c"] == 0:
            ingest.run_ingest(live=False, con=c)  # first start: load the offline demo data
    ingest.start_scheduler(_lock)  # live collection every AUTO_INGEST_MINUTES, if set


class WatchIn(BaseModel):
    kind: str = Field(max_length=10)  # "domain" | "email"
    value: str = Field(max_length=200)


class AnalyseIn(BaseModel):
    text: str = Field(max_length=20000)
    title: str = Field(default="", max_length=200)


class FeedbackIn(BaseModel):
    verdict: str = Field(max_length=10)  # "correct" | "wrong"
    category: str = Field(default="", max_length=40)  # what it should have been, required when wrong


def _alert_row(r) -> dict:
    d = dict(r)
    d["signals"] = json.loads(d["signals"])
    d["probs"] = json.loads(d["probs"])
    meta = json.loads(d.pop("meta", None) or "{}")
    d["demo"] = bool(meta.get("demo"))
    # Some sources (Ransomware.live) forbid re-publishing their raw data. We keep the text to score it, but never
    # return it from the API, and such alerts are left out of every export. The title, our score and the reasons,
    # and a link back to the source are shown, with attribution.
    d["restricted"] = bool(meta.get("no_redistribute"))
    if d["restricted"]:
        d["text"] = ""
    return d


def _rows(where: str = "", args: tuple = (), limit: int | None = None):
    q = ("SELECT a.*, i.source, i.kind, i.title, i.text, i.url, i.seen_at, i.actor, i.org, i.country, i.meta "
         "FROM alerts a JOIN items i ON i.id=a.item_id " + where + " ORDER BY a.score DESC, a.item_id")
    if limit:
        q += f" LIMIT {int(limit)}"
    return [_alert_row(r) for r in con().execute(q, args)]


def _iocs_for(item_id: str) -> dict:
    out: dict = {}
    for r in con().execute("SELECT type, value FROM iocs WHERE item_id=?", (item_id,)):
        out.setdefault(r["type"], []).append(r["value"])
    return out


def _all_iocs() -> dict[str, dict]:
    """Every indicator in one query, grouped by alert. One round trip instead of one per alert."""
    out: dict[str, dict] = {}
    for r in con().execute("SELECT item_id, type, value FROM iocs ORDER BY item_id, type, value"):
        out.setdefault(r["item_id"], {}).setdefault(r["type"], []).append(r["value"])
    return out


def _with_iocs(rows: list[dict]) -> list[dict]:
    m = _all_iocs()
    for r in rows:
        r["iocs"] = m.get(r["item_id"], {})
    return rows


def _client_ip(request: Request) -> str:
    if os.getenv("TRUST_PROXY") == "1":
        xff = request.headers.get("x-forwarded-for", "")
        if xff.split(",")[0].strip():
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _voter(request: Request) -> str:
    """An anonymous, salted hash so one visitor gets one vote per alert without storing their address."""
    raw = f"{os.getenv('VOTER_SALT', 'darklens')}|{_client_ip(request)}|{request.headers.get('user-agent', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _require_ingest_token(token: str | None):
    expected = os.getenv("INGEST_TOKEN", "")
    if expected and token != expected:
        raise HTTPException(401, "A valid X-Ingest-Token header is required.")


@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse(DASH)


@app.api_route("/api/health", methods=["GET", "HEAD"])
def health():
    """HEAD is allowed too, because uptime monitors (UptimeRobot) probe with HEAD and would otherwise see a 405."""
    return {"ok": True, "version": __version__, "storage": getattr(con(), "dialect", "sqlite")}


@app.get("/api/stats")
def stats():
    rows = _rows()
    sev = Counter(r["severity"] for r in rows)
    cat = Counter(r["category"] for r in rows)
    ioc_counts = Counter(r["type"] for r in con().execute("SELECT type FROM iocs"))
    demo = sum(1 for r in rows if r["demo"])
    return {"alerts": len(rows), "items": con().execute("SELECT COUNT(*) c FROM items").fetchone()["c"],
            "by_severity": dict(sev), "by_category": dict(cat), "ioc_types": dict(ioc_counts),
            "demo_alerts": demo, "real_alerts": len(rows) - demo,
            "attribution": "Source: Ransomware.live (victim claims). Demo data is synthetic."}


@app.get("/api/alerts")
def alerts(severity: str | None = None, category: str | None = None, q: str | None = None, limit: int = 1000):
    rows = _rows(limit=min(max(limit, 1), 5000))
    if severity:
        rows = [r for r in rows if r["severity"] == severity]
    if category:
        rows = [r for r in rows if r["category"] == category]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r["title"] + " " + r["text"]).lower()]
    return _with_iocs(rows)


@app.get("/api/alerts/{item_id}")
def alert(item_id: str):
    rows = _rows("WHERE a.item_id=?", (item_id,))
    if not rows:
        raise HTTPException(404, "alert not found")
    r = rows[0]
    r["iocs"] = _iocs_for(item_id)
    r["mitre"] = techniques(r["category"])
    votes = Counter(x["verdict"] for x in con().execute("SELECT verdict FROM feedback WHERE item_id=?", (item_id,)))
    r["feedback"] = {"correct": votes.get("correct", 0), "wrong": votes.get("wrong", 0)}
    return r


@app.post("/api/alerts/{item_id}/feedback")
def alert_feedback(item_id: str, body: FeedbackIn, request: Request):
    """Analyst feedback loop: 'this classification is right' or 'it should have been X'. One vote per visitor."""
    rows = _rows("WHERE a.item_id=?", (item_id,))
    if not rows:
        raise HTTPException(404, "alert not found")
    if body.verdict not in ("correct", "wrong"):
        raise HTTPException(400, "verdict must be 'correct' or 'wrong'")
    label = rows[0]["category"] if body.verdict == "correct" else body.category
    if label not in LABELS:
        raise HTTPException(400, f"category must be one of: {', '.join(sorted(LABELS))}")
    if body.verdict == "wrong" and label == rows[0]["category"]:
        raise HTTPException(400, "That is the category it already has. Choose the one it should have been.")
    db.feedback_set(con(), item_id, _voter(request), body.verdict, label, now_iso())
    return alert(item_id)["feedback"]


@app.get("/api/feedback/summary")
def feedback_summary():
    rows = db.feedback_all(con())
    correct = sum(1 for r in rows if r["verdict"] == "correct")
    return {"total": len(rows), "correct": correct, "wrong": len(rows) - correct,
            "agreement": round(correct / len(rows), 3) if rows else None,
            "corrections": dict(Counter(f"{r['predicted']} -> {r['category']}" for r in rows if r["verdict"] == "wrong"))}


@app.get("/api/export/feedback.csv", response_class=PlainTextResponse)
def export_feedback():
    """Analyst-confirmed labels, ready for `python -m darklens eval --csv`. Text is the stored, masked snippet."""
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["text", "label", "predicted", "item_id"])
    for r in db.feedback_all(con()):
        if json.loads(r.get("meta") or "{}").get("no_redistribute"):
            continue  # a source's terms forbid re-publishing its text
        w.writerow([export._safe_cell(f"{r['title']}. {r['text']}"), r["category"], r["predicted"], r["item_id"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="darklens-feedback.csv"'})


def _exportable() -> list[dict]:
    """Alerts that may be re-published: everything except sources whose terms forbid it (see _alert_row)."""
    return [r for r in _with_iocs(_rows(limit=5000)) if not r["restricted"]]


@app.get("/api/export/alerts.csv", response_class=PlainTextResponse)
def export_csv():
    return PlainTextResponse(export.to_csv(_exportable()), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="darklens-alerts.csv"'})


@app.get("/api/export/stix.json")
def export_stix():
    return JSONResponse(export.to_stix(_exportable()), media_type="application/stix+json;version=2.1",
                        headers={"Content-Disposition": 'attachment; filename="darklens-stix.json"'})


@app.get("/api/alerts/{item_id}/evidence", response_class=HTMLResponse)
def evidence(item_id: str):
    page, _ = build_pack(alert(item_id))
    return HTMLResponse(page)


@app.get("/api/graph")
def graph():
    rows = _with_iocs(_rows(limit=2000))
    for r in rows:
        r["id"] = r["item_id"]
    g = entities.build_graph(rows)
    return {"graph": entities.to_json(g), "linked_actors": entities.linked_actors(g),
            "campaigns": entities.campaigns(g)}


@app.get("/api/watchlist")
def watchlist():
    return [{"kind": k, "value": v} for k, v in db.watch_all(con())]


@app.post("/api/watchlist")
def watch_add(w: WatchIn):
    value = w.value.strip().lower()
    if w.kind not in ("domain", "email"):
        raise HTTPException(400, "kind must be domain or email")
    if not (_DOMAIN if w.kind == "domain" else _EMAIL).match(value):
        raise HTTPException(400, f"That does not look like a valid {w.kind}.")
    with _lock:
        c = con()
        db.watch_add(c, w.kind, value)
        pipeline.rescore(c)  # re-score everything stored (demo and live) against the new watchlist
        notify.dispatch(c)
    return watchlist()


@app.get("/api/ingest/status")
def ingest_status():
    return ingest.status(con())


@app.post("/api/ingest")
def run_ingest(offline: bool = True, x_ingest_token: str | None = Header(default=None)):
    _require_ingest_token(x_ingest_token)
    with _lock:
        return ingest.run_ingest(live=not offline, con=con())


@app.post("/api/analyse")
def analyse(body: AnalyseIn):
    """Analyse any pasted text. Nothing is stored."""
    wl = db.watch_all(con())
    a = pipeline.analyse(Item(source="manual", kind="post", title=body.title, text=body.text),
                         [v for k, v in wl if k == "domain"], [v for k, v in wl if k == "email"], get_classifier())
    return {"category": a.category, "confidence": round(a.confidence, 3), "score": a.score, "severity": a.severity,
            "signals": [s.to_dict() for s in a.signals], "iocs": a.iocs, "probs": a.probs,
            "exposures": a.exposures}


_eval_cache: dict = {}


@app.get("/api/eval")
def eval_metrics():
    """The result only changes when the model or rules change, so compute it once per process."""
    if not _eval_cache:
        r = evaluate(get_classifier())
        _eval_cache.update({k: v for k, v in r.items() if k != "report_hybrid"} | {
            "note": "Macro-F1 on held-out synthetic templates. See README Honest limitations."})
    return dict(_eval_cache)
