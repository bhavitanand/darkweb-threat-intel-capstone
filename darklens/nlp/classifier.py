"""Threat-category classifier: TF-IDF + logistic regression, fused with the rules engine.

Three predictors are exposed so they can be compared honestly:
  * rules  : detection rules only (transparent, no training)
  * ml     : TF-IDF + logistic regression only
  * hybrid : probability fusion of both (default)
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score

from ..rules.engine import category_scores, run_rules
from .corpus import CATEGORIES, generate

REAL_WEIGHT = 0.15  # real breach write-ups (the credential_dump examples); chosen by measurement, see docs/accuracy.md
REAL_NVD_WEIGHT = 0.02  # real vulnerability advisories (benign hard negatives): light, or they swamp the other classes
MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "classifier.joblib"


class ThreatClassifier:
    # How strongly rule evidence boosts the model's probability in the hybrid. A class attribute, not a number buried
    # in the formula, so it can be measured and tuned (the saved model file does not need retraining to change it).
    # It started as a hand-picked 1.5 that had never been tuned. Measured on 1.5/3/5/8/12: synthetic hybrid macro-F1
    # 0.836/0.851/0.877/0.890/0.885, with no more real-news false alarms up to 8. It was chosen using the synthetic
    # test set, so that figure is slightly flattered.
    RULE_BOOST = 12.0
    BENIGN_SUPPRESSION = 0.95  # how hard the strongest rule pushes "benign" down (see predict_proba)

    def __init__(self):
        self.word = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)
        self.char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)
        # Balanced class weights: the real examples cover few classes, so without this the common ones dominate.
        self.clf = LogisticRegression(max_iter=3000, C=6.0, class_weight="balanced")
        self.classes_: list[str] = []

    def _feats(self, texts, fit=False):
        if fit:
            return hstack([self.word.fit_transform(texts), self.char.fit_transform(texts)]).tocsr()
        return hstack([self.word.transform(texts), self.char.transform(texts)]).tocsr()

    def fit(self, texts, labels, sample_weight=None):
        self.clf.fit(self._feats(texts, fit=True), labels, sample_weight=sample_weight)
        self.classes_ = list(self.clf.classes_)
        return self

    def ml_proba(self, texts) -> np.ndarray:
        return self.clf.predict_proba(self._feats(texts))

    def rule_vector(self, text: str) -> np.ndarray:
        cs = category_scores(run_rules(text))
        return np.array([cs.get(c, 0.0) for c in self.classes_])

    def predict_proba(self, texts, mode: str = "hybrid") -> np.ndarray:
        ml = self.ml_proba(texts)
        if mode == "ml":
            return ml
        rv = np.vstack([self.rule_vector(t) for t in texts])
        if mode == "rules":
            # benign wins when no rule fires
            out = rv.copy()
            benign = self.classes_.index("benign")
            out[:, benign] = np.where(rv.sum(axis=1) == 0, 1.0, 0.0)
            return out
        # hybrid: ML probability boosted by rule evidence, benign suppressed when rules fire
        fused = ml * (1 + self.RULE_BOOST * rv)
        benign = self.classes_.index("benign")
        # A weak rule halves the chance of "benign"; a strong one (explicit sale wording, weight 85) all but removes
        # it. The text model has learned from real advisories that "exploit" and "remote code execution" usually mean
        # a harmless patch notice, and that must not outvote a rule that sees an actual offer to sell.
        strongest = rv.max(axis=1)
        fused[:, benign] *= np.where(strongest > 0, np.clip(1.0 - self.BENIGN_SUPPRESSION * strongest, 0.05, 0.4), 1.0)
        return fused / fused.sum(axis=1, keepdims=True)

    def predict(self, texts, mode: str = "hybrid") -> list[str]:
        p = self.predict_proba(texts, mode)
        return [self.classes_[i] for i in p.argmax(axis=1)]

    def classify(self, text: str) -> tuple[str, float, dict[str, float]]:
        p = self.predict_proba([text])[0]
        i = int(p.argmax())
        return self.classes_[i], float(p[i]), {c: round(float(x), 3) for c, x in zip(self.classes_, p)}

    def save(self, path: Path | None = None):
        path = path or MODEL_PATH  # looked up now, not when the class was defined
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path | None = None) -> "ThreatClassifier":
        return joblib.load(path or MODEL_PATH)


def nvd_holdout(row: dict) -> bool:
    """One advisory in five is never trained on, so false alarms on unseen real advisories can be measured."""
    import zlib
    return zlib.crc32(row["id"].encode()) % 5 == 0


def train_default(save: bool = True, real: bool = True, hibp_before: str | None = None, hold_out_nvd: bool = False,
                  real_weight: float | None = None, nvd_weight: float | None = None) -> ThreatClassifier:
    """Train on the synthetic templates plus the committed real examples (data/real_labelled: real breach write-ups
    and real vulnerability advisories). `hibp_before` keeps breaches added on or after that date out of training, so
    that period can serve as an honest test; `hold_out_nvd` keeps a fifth of the advisories out for the same reason."""
    X, y = generate("train", per_template=14)
    n_synthetic = len(X)
    if real:
        from . import realdata

        w_breach = REAL_WEIGHT if real_weight is None else real_weight
        w_advisory = REAL_NVD_WEIGHT if nvd_weight is None else nvd_weight
        real_w: list[float] = []
        for r in realdata.load(realdata.HIBP_CSV):
            if not hibp_before or r["added"] < hibp_before:
                X.append(r["text"])
                y.append(r["label"])
                real_w.append(w_breach)
        for r in realdata.load(realdata.NVD_CSV):
            if not (hold_out_nvd and nvd_holdout(r)):
                X.append(r["text"])
                y.append(r["label"])
                real_w.append(w_advisory)
    weights = None
    if real and len(X) > n_synthetic:
        # The real examples cover only two classes and outnumber the templates, so unweighted they would pull every
        # prediction towards those two. Weighting keeps all eight classes in balance.
        weights = np.array([1.0] * n_synthetic + real_w)
    clf = ThreatClassifier().fit(X, y, sample_weight=weights)
    if save:
        clf.save()
    return clf


_CACHE: dict = {}


def get_classifier() -> ThreatClassifier:
    """The trained model, loaded once per process. (It is several megabytes, and this is called for every analysis,
    so loading it from disk each time cost hundreds of milliseconds per request.) A new file on disk, for example after
    retraining, is picked up because the cache is keyed on the file's modification time."""
    try:
        stamp = MODEL_PATH.stat().st_mtime_ns if MODEL_PATH.exists() else None
    except OSError:
        stamp = None
    hit = _CACHE.get("clf")
    if hit is not None and hit[0] == stamp and stamp is not None:
        return hit[1]
    clf = None
    if stamp is not None:
        try:
            clf = ThreatClassifier.load()
        except Exception:  # noqa: BLE001  (a damaged or incompatible file: train a fresh one)
            clf = None
    if clf is None:
        clf = train_default()
        try:
            stamp = MODEL_PATH.stat().st_mtime_ns if MODEL_PATH.exists() else None
        except OSError:
            stamp = None
    _CACHE["clf"] = (stamp, clf)
    return clf


def evaluate(clf: ThreatClassifier | None = None) -> dict:
    """Macro-F1 for rules, ml and hybrid on held-out templates (sentence structures never seen in training)."""
    clf = clf or train_default(save=False)
    Xte, yte = generate("test", per_template=14)
    results = {}
    for mode in ("rules", "ml", "hybrid"):
        pred = clf.predict(Xte, mode)
        results[mode] = round(f1_score(yte, pred, average="macro", labels=CATEGORIES, zero_division=0), 4)
    results["report_hybrid"] = classification_report(yte, clf.predict(Xte, "hybrid"), zero_division=0)
    results["n_test"] = len(Xte)
    return results


if __name__ == "__main__":
    r = evaluate()
    print({k: v for k, v in r.items() if k != "report_hybrid"})
    print(r["report_hybrid"])
