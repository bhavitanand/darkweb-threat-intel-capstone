"""Evaluation on data that is NOT the synthetic training corpus.

The 84% headline number comes from synthetic templates, so it says the method works, not how well it does on real
text. These helpers measure what really matters, from three sources:

  1. a labelled CSV you provide (text,label)                -> macro-F1 per predictor, per-class results
  2. analyst feedback collected in the app                  -> how often reviewers agree with the system
  3. live Ransomware.live claims (public, real, one class)  -> what share of real claims are recognised
"""
from __future__ import annotations

import csv
from collections import Counter

from sklearn.metrics import classification_report, f1_score

from ..models import Item
from .corpus import CATEGORIES

MIN_TRUSTWORTHY = 50  # below this many labelled examples a macro-F1 is mostly noise


def load_csv(path: str, text_col: str = "text", label_col: str = "label") -> tuple[list[str], list[str]]:
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = {text_col, label_col} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing column(s): {', '.join(sorted(missing))}")
        for i, row in enumerate(reader, start=2):
            label = (row[label_col] or "").strip()
            if label not in CATEGORIES:
                raise ValueError(f"line {i}: label '{label}' is not one of {', '.join(CATEGORIES)}")
            if (row[text_col] or "").strip():
                texts.append(row[text_col])
                labels.append(label)
    if not texts:
        raise ValueError("no labelled rows found")
    return texts, labels


def score_labelled(clf, texts: list[str], labels: list[str]) -> dict:
    out: dict = {"n": len(texts), "class_counts": dict(Counter(labels)), "macro_f1": {}}
    for mode in ("rules", "ml", "hybrid"):
        pred = clf.predict(texts, mode)
        out["macro_f1"][mode] = round(f1_score(labels, pred, average="macro", labels=sorted(set(labels)), zero_division=0), 4)
        if mode == "hybrid":
            out["report"] = classification_report(labels, pred, zero_division=0)
            out["accuracy"] = round(sum(p == y for p, y in zip(pred, labels)) / len(labels), 4)
    out["warning"] = (f"Only {len(texts)} examples: treat these numbers as a rough guide." if len(texts) < MIN_TRUSTWORTHY else "")
    return out


def score_feedback(clf, rows: list[dict]) -> dict:
    """rows come from `db.feedback_all`. Reports agreement and re-scores the hybrid on the reviewers' labels."""
    if not rows:
        return {"n": 0, "warning": "No feedback yet. Use 'Is this right?' on an alert report."}
    texts = [f"{r['title']}. {r['text']}" for r in rows]
    labels = [r["category"] for r in rows]
    usable = [(t, y) for t, y in zip(texts, labels) if y in CATEGORIES]
    out = {"n": len(rows), "agreement": round(sum(r["verdict"] == "correct" for r in rows) / len(rows), 4)}
    if usable:
        out.update(score_labelled(clf, [t for t, _ in usable], [y for _, y in usable]))
    return out


def live_claims_check(clf, items: list[Item], analyse) -> dict:
    """Real ransomware victim claims are all one class, so this measures recall for that class only."""
    rows = []
    for it in items:
        a = analyse(it, [], [], clf)
        rows.append((a.category, a.score, a.severity, it.title))
    n = len(rows)
    leak = sum(1 for c, *_ in rows if c == "ransomware_leak")
    flagged = sum(1 for _, s, sev, _t in rows if sev in ("medium", "high", "critical"))
    missed = sorted((r for r in rows if r[0] != "ransomware_leak"), key=lambda r: r[1])[:5]
    return {"n": n, "recognised_as_ransomware_leak": leak, "recall": round(leak / n, 3) if n else None,
            "scored_medium_or_higher": flagged, "share_medium_or_higher": round(flagged / n, 3) if n else None,
            "lowest_scoring_missed": [{"title": t, "category": c, "score": s} for c, s, _sev, t in missed]}
