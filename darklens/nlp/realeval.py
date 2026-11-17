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
MIN_PER_CLASS = 10    # below this many examples of one class, that class is reported as "too few to score"


def load_csv(path: str, text_col: str = "text", label_col: str = "label") -> tuple[list[str], list[str]]:
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = {text_col, label_col} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing column(s): {', '.join(sorted(missing))}")
        for i, row in enumerate(reader, start=2):
            label = (row[label_col] or "").strip()
            if label == "skip":
                continue  # out of scope or unjudgeable (see docs/labelling.md): not scored
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


def score_pipeline(clf, texts: list[str], labels: list[str], analyse) -> dict:
    """Score the product as a visitor experiences it, not just the text model.

    A text counts as 'predicted X' only if DarkLens would raise an alert for it with category X. No alert, or "Not
    sure", counts as 'benign'. So this measures the model, the rules, the "Not sure" cut and the scoring together,
    and adds the two numbers a user feels: how many real threats get no alert, and how often ordinary text does.
    """
    preds, scores = [], []
    for t in texts:
        a = analyse(Item(source="manual", kind="post", title="", text=t), [], [], clf)
        preds.append(a.category if a.score > 0 and a.category in CATEGORIES else "benign")
        scores.append((a.score, a.severity))
    n = len(texts)
    classes = sorted(set(labels) | set(preds))
    threats = [i for i, y in enumerate(labels) if y != "benign"]
    benign = [i for i, y in enumerate(labels) if y == "benign"]
    missed = [i for i in threats if scores[i][0] == 0]
    false_alarm = [i for i in benign if scores[i][0] > 0]
    false_alarm_medium = [i for i in benign if scores[i][1] in ("medium", "high", "critical")]
    wrong_type = [i for i in threats if scores[i][0] > 0 and preds[i] != labels[i]]
    confusions = Counter((labels[i], preds[i]) for i in range(n) if labels[i] != preds[i])
    severity_of_threats = Counter(scores[i][1] for i in threats if scores[i][0] > 0)
    rate = lambda a, b: round(len(a) / len(b), 4) if b else None  # noqa: E731
    counts = Counter(labels)
    scored = sorted(c for c, k in counts.items() if k >= MIN_PER_CLASS)
    return {
        "n": n, "class_counts": dict(counts),
        # A class with only a handful of examples cannot be scored fairly: one example is worth 20 points of recall.
        "classes_scored": scored,
        "classes_too_few_to_score": sorted(c for c, k in counts.items() if k < MIN_PER_CLASS),
        "macro_f1_scored_classes": (round(f1_score(labels, preds, average="macro", labels=scored, zero_division=0), 4) if scored else None),
        "macro_f1": round(f1_score(labels, preds, average="macro", labels=sorted(set(labels)), zero_division=0), 4),
        "accuracy": round(sum(p == y for p, y in zip(preds, labels)) / n, 4) if n else None,
        "report": classification_report(labels, preds, labels=classes, zero_division=0),
        "threats_missed_rate": rate(missed, threats),
        "threats_wrong_type_rate": rate(wrong_type, threats),
        "false_alarm_rate": rate(false_alarm, benign),
        "false_alarm_medium_or_higher_rate": rate(false_alarm_medium, benign),
        "severity_of_detected_threats": dict(severity_of_threats),
        "top_confusions": [(a, b, c) for (a, b), c in confusions.most_common(6)],
        "warning": (f"Only {n} examples: treat these numbers as a rough guide." if n < MIN_TRUSTWORTHY else ""),
    }


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


def holdout_report(test_from: str = "2026-01-01") -> dict:
    """The honest protocol on the committed real data, reproducible by anyone with the repository.

    A model is trained on the synthetic templates plus every real breach write-up added BEFORE `test_from` and 80% of
    the real advisories, then measured on what it never saw: the breaches added on or after `test_from`, and the other
    20% of the advisories. Breaches are measured by how many raise an alert and how many get the right type;
    advisories (benign by the labelling policy) by how many wrongly raise an alert.
    """
    from .. import pipeline
    from . import realdata
    from .classifier import nvd_holdout, train_default

    clf = train_default(save=False, real=True, hibp_before=test_from, hold_out_nvd=True)
    breaches = [r for r in realdata.load(realdata.HIBP_CSV) if r["added"] >= test_from]
    advisories = [r for r in realdata.load(realdata.NVD_CSV) if nvd_holdout(r)]

    def run(rows):
        out = []
        for r in rows:
            a = pipeline.analyse(Item(source="manual", kind="post", title="", text=r["text"]), [], [], clf)
            out.append((a.score > 0, a.category, a.severity))
        return out

    b, v = run(breaches), run(advisories)
    nb, nv = max(len(b), 1), max(len(v), 1)
    return {
        "test_from": test_from, "breaches_tested": len(b), "advisories_tested": len(v),
        "breach_alert_rate": round(sum(x[0] for x in b) / nb, 4),
        "breach_right_type_rate": round(sum(1 for x in b if x[0] and x[1] == "credential_dump") / nb, 4),
        "breach_medium_or_higher_rate": round(sum(1 for x in b if x[0] and x[2] in ("medium", "high", "critical")) / nb, 4),
        "advisory_false_alarm_rate": round(sum(x[0] for x in v) / nv, 4),
        "advisory_false_alarm_medium_or_higher_rate": round(sum(1 for x in v if x[0] and x[2] in ("medium", "high", "critical")) / nv, 4),
    }
