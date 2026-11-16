"""Collecting data on a schedule, with a per-source status the website can show.

Each source runs on its own, so one feed being down never stops the others, and every run records what worked,
what was skipped (for example no abuse.ch key set) and what failed. The status is stored in the database so it
survives restarts and is the same for every visitor.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone

from . import notify, pipeline
from .collectors import cisa_kev, forums, ransomware_live, threatfox, urlhaus
from .models import Item, now_iso
from .store import db

log = logging.getLogger("darklens.ingest")

STATUS_KEY = "ingest_status"
MIN_INTERVAL_MINUTES = 30  # Ransomware.live fair-use rule: no more than one fetch per 30 minutes


def _collect_one(name: str, fn, live: bool) -> tuple[list[Item], dict]:
    if live and name in ("threatfox", "urlhaus") and not os.environ.get("ABUSECH_AUTH_KEY"):
        return [], {"source": name, "status": "skipped", "items": 0, "note": "No abuse.ch key configured."}
    if live and name == "ransomware.live" and not os.environ.get(ransomware_live.KEY_ENV, "").strip():
        return [], {"source": name, "status": "skipped", "items": 0,
                    "note": "No Ransomware.live API key configured (the free key is required by their terms)."}
    if live and name == "forums":
        return [], {"source": name, "status": "skipped", "items": 0, "note": "Live forum posts need the Tor crawler."}
    try:
        items = fn(offline=not live)
        return items, {"source": name, "status": "ok", "items": len(items), "note": ""}
    except Exception as e:  # noqa: BLE001 - a broken feed must never stop the run
        log.warning("source %s failed: %s", name, e)
        return [], {"source": name, "status": "error", "items": 0, "note": f"{type(e).__name__}: {str(e)[:160]}"}


def run_ingest(live: bool, con=None) -> dict:
    """Collect from every source, score, store, notify, and record the outcome. Returns the stored status."""
    con = con or db.connect()
    started = now_iso()
    items: list[Item] = []
    sources: list[dict] = []
    for name, fn in (("ransomware.live", ransomware_live.fetch), ("threatfox", threatfox.fetch),
                     ("urlhaus", urlhaus.fetch), ("cisa-kev", cisa_kev.fetch), ("forums", forums.fetch)):
        got, status = _collect_one(name, fn, live)
        if not live:
            for it in got:
                it.meta["demo"] = True  # synthetic: shown with a Demo badge, never used for alerts to people
        items += got
        sources.append(status)
    result = pipeline.run(offline=not live, con=con, items=items)
    pruned = 0
    if live:
        def cutoff(d: int) -> str:
            return (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%Y-%m-%d")

        days, feed_days = _retention_days(), _feed_retention_days()
        if days:
            pruned += db.prune(con, cutoff(days), exclude_kinds=("ioc",))
        if feed_days:  # indicators go stale fast and arrive by the thousand, so they expire sooner
            pruned += db.prune(con, cutoff(feed_days), kinds=("ioc",))
    sent = notify.dispatch(con)
    state = {"started_at": started, "finished_at": now_iso(), "mode": "live" if live else "demo",
             "items": result["items"], "alerts": result["alerts"], "sources": sources, "notified": sent, "pruned": pruned,
             "ok": all(s["status"] != "error" for s in sources)}
    db.kv_set(con, STATUS_KEY, state)
    return state


def status(con=None) -> dict:
    con = con or db.connect()
    last = db.kv_get(con, STATUS_KEY)
    # "Live" only when a live run really collected from at least one source; a run where every source was skipped
    # (no keys yet) must not make the site claim live data.
    live_ready = last is not None and last.get("mode") == "live" and any(
        s["status"] == "ok" and s["items"] > 0 for s in last.get("sources", []))
    return {"last": last, "auto_ingest_minutes": interval_minutes(), "live_ready": live_ready}


def _days_env(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default) or 0))
    except ValueError:
        return default


def _retention_days() -> int:
    """How long real claims and posts are kept (RETENTION_DAYS, default 90, 0 keeps everything)."""
    return _days_env("RETENTION_DAYS", 90)


def _feed_retention_days() -> int:
    """How long indicator-feed entries are kept (FEED_RETENTION_DAYS, default 14, 0 keeps everything)."""
    return _days_env("FEED_RETENTION_DAYS", 14)


def interval_minutes() -> int:
    try:
        n = int(os.environ.get("AUTO_INGEST_MINUTES", "0") or 0)
    except ValueError:
        return 0
    return 0 if n <= 0 else max(n, MIN_INTERVAL_MINUTES)


_started = False


def start_scheduler(lock: threading.Lock, first_delay: int = 20) -> threading.Thread | None:
    """Start the background collector once per process. Off unless AUTO_INGEST_MINUTES is set."""
    global _started
    minutes = interval_minutes()
    if minutes == 0 or _started:
        return None
    _started = True

    def loop():
        time.sleep(first_delay)
        while True:
            try:
                with lock:
                    state = run_ingest(live=True)
                log.info("auto ingest: %s items, %s alerts", state["items"], state["alerts"])
            except Exception:  # noqa: BLE001
                log.exception("auto ingest failed")
            time.sleep(minutes * 60)

    t = threading.Thread(target=loop, name="darklens-ingest", daemon=True)
    t.start()
    return t
