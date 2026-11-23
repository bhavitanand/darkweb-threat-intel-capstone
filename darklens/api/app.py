"""FastAPI backend plus the original single-page dashboard. Run: uvicorn darklens.api.app:app --reload"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .. import __version__, enrich, export, ingest, notify, observability, pipeline
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
LABELS = set(CATEGORIES) | {"ioc_feed", "known_exploited", "uncertain"}

_DOMAIN = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")  # labels: no leading or trailing hyphen, at most 63 characters
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
WATCHLIST_MAX = 100
_PRODUCT = re.compile(r"^[a-z0-9][a-z0-9 .+_#-]{1,58}[a-z0-9+#]$")  # a product or vendor name such as "screenconnect"


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


observability.init()


@app.middleware("http")
async def _reject_nul(request: Request, call_next):
    """A NUL character (%00) in the address or search cannot be stored by Postgres and used to cause a 500. Nothing legitimate
    contains one, so refuse it up front with a plain message."""
    nul = chr(0)
    if any("%00" in part.lower() or nul in part for part in (request.url.query, request.url.path)):
        return JSONResponse({"detail": "That input contains a character that is not allowed."}, status_code=400)
    return await call_next(request)


@app.exception_handler(Exception)
async def _unexpected(request: Request, exc: Exception):
    """Odd input that the database refuses (a NUL character inside a JSON body, for example) is the caller's problem, not
    ours: answer 400 instead of a bare 500. Anything else stays a 500 (and reaches Sentry when it is set up)."""
    if type(exc).__module__.startswith("psycopg") and type(exc).__name__ in ("DataError", "ProgrammingError", "DataException"):
        return JSONResponse({"detail": "That input contains characters that cannot be stored."}, status_code=400)
    raise exc


# Order matters: middleware added last is outermost. CORS goes last so even a 429 carries CORS headers.
app.add_middleware(RateLimitMiddleware, read_per_min=_int_env("RATE_LIMIT_PER_MIN", 120),
                   write_per_min=_int_env("RATE_LIMIT_WRITE_PER_MIN", 20),
                   trust_proxy=os.getenv("TRUST_PROXY") == "1")

# CORS: the React frontend is served from a different origin (Vercel). Comma-separated exact origins in
# ALLOWED_ORIGINS (for example https://darklens.vercel.app). Unset means same-origin only, which is what the
# built-in dashboard and local development (Vite proxies /api) need.
_ORIGINS = [o.strip().rstrip("/") for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=_ORIGINS, allow_methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
                       allow_headers=["Content-Type", "X-Ingest-Token", "Authorization", "X-API-Key"], expose_headers=["X-Total-Count"], max_age=600)


def con():
    """SQLite: a short-lived connection per call. Postgres: the shared, reconnecting connection."""
    return db.connect()


from .account_routes import build_router  # noqa: E402

app.include_router(build_router(lambda: con(), _lock))


@app.on_event("startup")
def seed():
    with _lock:
        c = db.connect()
        if c.execute("SELECT COUNT(*) c FROM items").fetchone()["c"] == 0:
            ingest.run_ingest(live=False, con=c)  # first start: load the offline demo data
    ingest.start_scheduler(_lock)  # live collection every AUTO_INGEST_MINUTES, if set


class WatchIn(BaseModel):
    kind: str = Field(max_length=10)  # "domain" | "email" | "product"
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


def _rows(where: str = "", args: tuple = (), limit: int | None = None, offset: int = 0):
    q = ("SELECT a.*, i.source, i.kind, i.title, i.text, i.url, i.seen_at, i.actor, i.org, i.country, i.meta "
         "FROM alerts a JOIN items i ON i.id=a.item_id " + where + " ORDER BY a.score DESC, a.item_id")
    if limit:
        q += f" LIMIT {int(limit)}"
        if offset:
            q += f" OFFSET {int(offset)}"
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


def _require_ingest_token(token: str | None, live: bool = False):
    """Demo loading is harmless, so it is open unless a token is set. A LIVE collection makes the server fetch from
    outside and holds the database for the duration, so it is refused unless INGEST_TOKEN is configured and supplied
    (the scheduled collection, AUTO_INGEST_MINUTES, does not go through this endpoint)."""
    expected = os.getenv("INGEST_TOKEN", "")
    if live and not expected:
        raise HTTPException(403, "Live collection through the API is switched off. Set INGEST_TOKEN on the server to enable it, "
                                 "or use AUTO_INGEST_MINUTES.")
    if expected and not hmac.compare_digest((token or "").encode(), expected.encode()):
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
def alerts(response: Response, severity: str | None = None, category: str | None = None, q: str | None = None,
           data: str | None = None, limit: int = 1000, offset: int = 0):
    """Alerts, highest score first. Filtering and paging happen in the database, so a page costs the same however many
    alerts exist. The `X-Total-Count` header is the number of alerts matching the filters (before limit and offset).
    `data` is "real" or "demo"."""
    clauses, args = [], []
    if severity:
        clauses.append("a.severity=?")
        args.append(severity)
    if category:
        clauses.append("a.category=?")
        args.append(category)
    if data in ("real", "demo"):
        clauses.append("i.meta " + ("" if data == "demo" else "NOT ") + "LIKE '%\"demo\": true%'")
    if q:
        like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        # Text a source forbids re-publishing is never returned, so it must not be searchable either (a search that
        # reveals whether hidden text contains a word would leak it). Those alerts match on their title only.
        clauses.append("LOWER(COALESCE(i.title,'') || ' ' || CASE WHEN i.meta LIKE '%\"no_redistribute\": true%' "
                       "THEN '' ELSE COALESCE(i.text,'') END) LIKE ? ESCAPE '\\'")
        args.append(like)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = con().execute("SELECT COUNT(*) c FROM alerts a JOIN items i ON i.id=a.item_id " + where, tuple(args)).fetchone()["c"]
    response.headers["X-Total-Count"] = str(total)
    # Clamped, not rejected: an absurd offset (beyond what the database can hold) returns an empty page, never a 500.
    return _with_iocs(_rows(where, tuple(args), limit=min(max(limit, 1), 5000), offset=min(max(offset, 0), 10**9)))


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


@app.get("/api/enrich")
def enrich_indicator(kind: str = Query(..., max_length=10), value: str = Query(..., max_length=300)):
    """Reputation of one indicator from the outside services whose free key is set (none set: an empty answer)."""
    if kind not in enrich.SUPPORTED:
        raise HTTPException(400, f"Supported types: {', '.join(enrich.SUPPORTED)}.")
    try:
        return enrich.lookup(kind, value)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/export/misp.json")
def export_misp():
    return JSONResponse(export.to_misp(_exportable()), headers={"Content-Disposition": 'attachment; filename="darklens-misp.json"'})


def _taxii(body: dict) -> JSONResponse:
    return JSONResponse(body, media_type=export.TAXII_TYPE)


@app.get("/taxii2/")
def taxii_discovery(request: Request):
    return _taxii(export.taxii_discovery(str(request.base_url).rstrip("/")))


@app.get("/taxii2/root/")
def taxii_root():
    return _taxii(export.taxii_root())


@app.get("/taxii2/root/collections/")
def taxii_collections():
    return _taxii({"collections": [export.taxii_collection()]})


@app.get("/taxii2/root/collections/{cid}/")
def taxii_collection(cid: str):
    if cid != export.TAXII_COLLECTION_ID:
        raise HTTPException(404, "No such collection.")
    return _taxii(export.taxii_collection())


@app.get("/taxii2/root/collections/{cid}/objects/")
def taxii_objects(cid: str, limit: int = Query(500, ge=1, le=1000), next: str = "0", match_type: str = Query("", alias="match[type]")):
    if cid != export.TAXII_COLLECTION_ID:
        raise HTTPException(404, "No such collection.")
    try:
        offset = max(0, min(int(next), 10**9))
    except ValueError:
        raise HTTPException(400, "Bad 'next' value.")
    types = {t.strip() for t in match_type.split(",") if t.strip()} or None
    return _taxii(export.taxii_objects(_exportable(), limit, offset, types))


@app.get("/api/alerts/{item_id}/evidence", response_class=HTMLResponse)
def evidence(item_id: str):
    page, _ = build_pack(alert(item_id))
    return HTMLResponse(page)


GRAPH_MAX_ALERTS = 300


@app.get("/api/graph")
def graph():
    """The connection map. Indicator-feed entries (over a thousand a day from ThreatFox) are left out: each is a
    lone indicator with nothing to connect, and they would bury the posts, posters and wallets that do connect.
    The highest-scoring GRAPH_MAX_ALERTS alerts are shown so the picture stays readable."""
    rows = [r for r in _with_iocs(_rows(limit=2000)) if r["category"] != "ioc_feed"][:GRAPH_MAX_ALERTS]
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
    if w.kind not in ("domain", "email", "product"):
        raise HTTPException(400, "kind must be domain, email or product")
    if not {"domain": _DOMAIN, "email": _EMAIL, "product": _PRODUCT}[w.kind].match(value):
        raise HTTPException(400, f"That does not look like a valid {w.kind}.")
    with _lock:
        c = con()
        existing = db.watch_all(c)
        if (w.kind, value) not in existing and len(existing) >= WATCHLIST_MAX:
            # Nobody can remove entries yet and the list is shared, so it must not be allowed to grow without limit.
            raise HTTPException(400, f"The shared watchlist is full ({WATCHLIST_MAX} entries). Run your own copy of DarkLens for more.")
        db.watch_add(c, w.kind, value)
        # Only items that mention the new entry can change, so only those are re-scored (all stored items, demo and live).
        pipeline.rescore(c, contains=value)
        notify.dispatch(c)
    return watchlist()


@app.get("/api/ingest/status")
def ingest_status():
    return ingest.status(con())


@app.post("/api/ingest")
def run_ingest(offline: bool = True, x_ingest_token: str | None = Header(default=None)):
    _require_ingest_token(x_ingest_token, live=not offline)
    with _lock:
        return ingest.run_ingest(live=not offline, con=con())


@app.post("/api/analyse")
def analyse(body: AnalyseIn):
    """Analyse any pasted text. Nothing is stored."""
    wl = db.watch_all(con())
    a = pipeline.analyse(Item(source="manual", kind="post", title=body.title, text=body.text),
                         [v for k, v in wl if k == "domain"], [v for k, v in wl if k == "email"], get_classifier(),
                         [v for k, v in wl if k == "product"])
    return {"category": a.category, "confidence": round(a.confidence, 3), "score": a.score, "severity": a.severity,
            "signals": [s.to_dict() for s in a.signals], "iocs": a.iocs, "probs": a.probs,
            "exposures": a.exposures, "truncated": a.truncated}


_eval_cache: dict = {}


@app.get("/api/eval")
def eval_metrics():
    """The result only changes when the model or rules change, so compute it once per process."""
    if not _eval_cache:
        r = evaluate(get_classifier())
        _eval_cache.update({k: v for k, v in r.items() if k != "report_hybrid"} | {
            "note": "Macro-F1 on held-out synthetic templates. See README Honest limitations."})
    return dict(_eval_cache)
