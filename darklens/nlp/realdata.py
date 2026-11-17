"""Real, freely redistributable text for training and measuring the classifier.

Two public sources, both needing no key and no login:

  * Have I Been Pwned breach list (https://haveibeenpwned.com/api/v3/breaches), licensed CC BY 4.0. Each entry is a
    real, verified data breach with a prose write-up, so every one is a real example of `credential_dump`.
  * NIST National Vulnerability Database (https://nvd.nist.gov), US government data in the public domain. Each entry
    describes a software flaw: security vocabulary, but an advisory, not a threat post. Under the labelling policy
    (docs/labelling.md) a vulnerability notice with no sale and no incident is `benign`, so these are real hard
    negatives, the kind of text that makes a model cry wolf.

`python -m darklens data build` fetches both and writes data/real_labelled/*.csv. The CSVs are committed so training
does not need the network; attribution is in data/real_labelled/README.md.
"""
from __future__ import annotations

import csv
import html
import re
import time
from datetime import date, timedelta
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "real_labelled"
HIBP_CSV = DATA_DIR / "hibp_breaches.csv"
NVD_CSV = DATA_DIR / "nvd_advisories.csv"
UA = {"User-Agent": "DarkLens-research/0.1 (academic capstone; non-commercial)"}
COLUMNS = ["id", "source", "added", "label", "text"]


def clean_html(s: str | None) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s or "")).split())


def fetch_hibp(get=None) -> list[dict]:
    """Every usable breach write-up. Spam lists and fabricated entries are not real breaches of a real service."""
    import requests

    get = get or (lambda u: requests.get(u, headers=UA, timeout=60).json())
    out = []
    for b in get("https://haveibeenpwned.com/api/v3/breaches"):
        text = clean_html(b.get("Description"))
        if b.get("IsSpamList") or b.get("IsFabricated") or len(text) < 40:
            continue
        out.append({"id": f"hibp-{b['Name']}", "source": "haveibeenpwned.com", "added": (b.get("AddedDate") or "")[:10],
                    "label": "credential_dump", "text": text})
    return out


def fetch_nvd(windows: int = 6, per_window: int = 180, get=None, pause: float = 7.0) -> list[dict]:
    """English descriptions of recent vulnerabilities, spread over several date windows. Without a key NVD allows
    5 requests per 30 seconds, hence the pause."""
    import requests

    get = get or (lambda u: requests.get(u, headers=UA, timeout=60).json())
    out: list[dict] = []
    end = date(2026, 11, 1)
    for w in range(windows):
        stop = end - timedelta(days=100 * w)
        start = stop - timedelta(days=90)
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000"
               f"&pubStartDate={start.isoformat()}T00:00:00.000&pubEndDate={stop.isoformat()}T23:59:59.999")
        try:
            data = get(url)
        except Exception:  # noqa: BLE001  (one window failing must not lose the rest)
            time.sleep(pause)
            continue
        items = data.get("vulnerabilities") or []
        step = max(1, len(items) // per_window)
        for v in items[::step][:per_window]:
            c = v.get("cve") or {}
            desc = next((d.get("value") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            desc = " ".join((desc or "").split())
            low = desc.lower()[:60]
            # NVD marks a withdrawn entry "** REJECT **" (or "** DISPUTED **" when contested): not a real description.
            if len(desc) >= 40 and "** reject" not in low and "rejected" not in low and "** disputed" not in low:
                out.append({"id": c.get("id", ""), "source": "nvd.nist.gov", "added": (c.get("published") or "")[:10],
                            "label": "benign", "text": desc[:600]})
        time.sleep(pause)
    return out


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["added"], r["id"])))


def load(path: Path) -> list[dict]:
    if not Path(path).exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def training_rows(before: str | None = None) -> list[dict]:
    """The committed real examples, optionally only those added before a date (`YYYY-MM-DD`). That is how a held-out
    period is kept out of training so it can be used as an honest test."""
    rows = load(HIBP_CSV) + load(NVD_CSV)
    return [r for r in rows if not before or (r["added"] and r["added"] < before)]


def build() -> dict:
    hibp, nvd = fetch_hibp(), fetch_nvd()
    write_csv(HIBP_CSV, hibp)
    write_csv(NVD_CSV, nvd)
    return {"hibp": len(hibp), "nvd": len(nvd)}
