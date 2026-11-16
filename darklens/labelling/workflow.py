"""Sampling, labelling sheets, agreement statistics, consensus and the dev/test split."""
from __future__ import annotations

import csv
import difflib
import itertools
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from ..nlp.corpus import CATEGORIES

THREAT_CLASSES = [c for c in CATEGORIES if c != "benign"]
LABELS = list(CATEGORIES)          # what a labeller may write
SKIP = "skip"                      # unusable: not text, truncated, impossible to judge
REVIEW = "REVIEW"                  # consensus could not be reached, the team must decide
SHEET_COLUMNS = ["id", "text", "label", "notes"]


# ---------------- sampling ----------------

def select(pool: list[dict], hint, total: int = 300, per_class: int = 30, seed: int = 7) -> tuple[list[dict], dict]:
    """Pick `total` items so that every class has a fair chance of appearing.

    `hint(text)` is a cheap guess of the class (the classifier plus rules), used ONLY to find rare classes in a pile
    of mostly ordinary news. It is never written to the sheets, so labellers are not biased by it. Because rare
    classes are over-sampled, the share of threats in the final set is higher than in real life: it is for
    measuring per-class accuracy, not for estimating how common threats are.
    """
    rng = random.Random(seed)
    items = list(pool)
    rng.shuffle(items)
    by_hint: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by_hint[hint(it["text"])].append(it)
    chosen: list[dict] = []
    taken: set[str] = set()
    found = {}
    for c in THREAT_CLASSES:
        found[c] = len(by_hint.get(c, []))
        for it in by_hint.get(c, [])[:per_class]:
            chosen.append(it)
            taken.add(it["id"])
    rest = [it for it in items if it["id"] not in taken]
    # prefer ordinary (general) text for the rest: it is what the false-alarm measurement needs
    rest.sort(key=lambda it: 0 if it.get("kind") == "general" else 1)
    for it in rest:
        if len(chosen) >= total:
            break
        chosen.append(it)
    rng.shuffle(chosen)
    return chosen[:total], {"candidates_per_class": found, "pool": len(pool)}


# ---------------- sheets ----------------

def assign(items: list[dict], names: list[str], shared: int = 40, seed: int = 11) -> dict[str, list[dict]]:
    """The first `shared` items go to everybody (each in their own order); the rest are dealt out round-robin."""
    if not names:
        raise ValueError("at least one labeller name is needed")
    shared = min(shared if len(names) > 1 else 0, len(items))
    rng = random.Random(seed)
    items = list(items)
    rng.shuffle(items)
    common, rest = items[:shared], items[shared:]
    out: dict[str, list[dict]] = {n: [] for n in names}
    for i, it in enumerate(rest):
        out[names[i % len(names)]].append(it)
    for n in names:
        mine = list(common)
        random.Random(f"{seed}-{n}").shuffle(mine)
        out[n] = mine + out[n]
        random.Random(f"{seed}-{n}-all").shuffle(out[n])
    return out


def write_sheet(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig so Excel opens accents correctly
        w = csv.writer(f)
        w.writerow(SHEET_COLUMNS)
        for it in items:
            w.writerow([it["id"], it["text"], "", ""])


def read_sheet(path: Path) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Returns ({id: (label, text)} for labelled rows, [problems]). Problems say exactly which row and why."""
    rows: dict[str, tuple[str, str]] = {}
    problems: list[str] = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = {"id", "text", "label"} - set(reader.fieldnames or [])
        if missing:
            return {}, [f"{path.name}: missing column(s) {', '.join(sorted(missing))}"]
        for n, r in enumerate(reader, start=2):
            label = (r.get("label") or "").strip().lower().replace(" ", "_")
            if not label:
                continue  # not labelled yet
            if label not in LABELS and label != SKIP:
                hint = difflib.get_close_matches(label, LABELS + [SKIP], n=1)
                problems.append(f"{path.name} line {n}: '{label}' is not a valid label"
                                + (f" (did you mean '{hint[0]}'?)" if hint else ""))
                continue
            rows[r["id"]] = (label, r["text"])
    return rows, problems


def progress(sheet: Path) -> tuple[int, int]:
    with open(sheet, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    return sum(1 for r in rows if (r.get("label") or "").strip()), len(rows)


def collect(sheets_dir: Path) -> tuple[dict[str, dict[str, tuple[str, str]]], list[str], dict[str, tuple[int, int]]]:
    by_person, problems, prog = {}, [], {}
    for p in sorted(Path(sheets_dir).glob("*.csv")):
        rows, probs = read_sheet(p)
        by_person[p.stem] = rows
        problems += probs
        prog[p.stem] = progress(p)
    return by_person, problems, prog


# ---------------- agreement ----------------

def cohen_kappa(a: list[str], b: list[str]) -> float:
    from sklearn.metrics import cohen_kappa_score

    if len(a) < 2 or len(set(a) | set(b)) < 2:
        return float("nan")
    return float(cohen_kappa_score(a, b))


def fleiss_kappa(ratings: list[list[str]]) -> float:
    """Agreement across any number of labellers. Each inner list holds one item's labels (same length each)."""
    n_items = len(ratings)
    if n_items == 0:
        return float("nan")
    n = len(ratings[0])
    cats = sorted({c for r in ratings for c in r})
    counts = [[r.count(c) for c in cats] for r in ratings]
    p_i = [(sum(x * x for x in row) - n) / (n * (n - 1)) for row in counts]
    p_bar = sum(p_i) / n_items
    p_j = [sum(row[j] for row in counts) / (n_items * n) for j in range(len(cats))]
    p_e = sum(x * x for x in p_j)
    return float("nan") if p_e == 1 else (p_bar - p_e) / (1 - p_e)


def agreement(by_person: dict[str, dict[str, tuple[str, str]]]) -> dict:
    """Agreement on the items several people labelled (skips excluded)."""
    people = [p for p, rows in by_person.items() if rows]
    ids = Counter(i for p in people for i, (lab, _t) in by_person[p].items() if lab != SKIP)
    shared = sorted(i for i, c in ids.items() if c >= 2)
    out: dict = {"people": people, "shared_items": len(shared), "pairs": {}, "per_class_disagreements": {}, "disagreements": []}
    if not shared:
        return out
    for p, q in itertools.combinations(people, 2):
        both = [i for i in shared if i in by_person[p] and i in by_person[q] and SKIP not in (by_person[p][i][0], by_person[q][i][0])]
        if both:
            la, lb = [by_person[p][i][0] for i in both], [by_person[q][i][0] for i in both]
            out["pairs"][f"{p}~{q}"] = {"n": len(both), "agree": round(sum(x == y for x, y in zip(la, lb)) / len(both), 3),
                                        "kappa": round(cohen_kappa(la, lb), 3)}
    full = [i for i in shared if all(i in by_person[p] and by_person[p][i][0] != SKIP for p in people)]
    if len(people) >= 2 and full:
        out["fleiss_kappa"] = round(fleiss_kappa([[by_person[p][i][0] for p in people] for i in full]), 3)
        out["items_labelled_by_everyone"] = len(full)
    wrong: Counter = Counter()
    for i in shared:
        labs = {p: by_person[p][i][0] for p in people if i in by_person[p] and by_person[p][i][0] != SKIP}
        if len(set(labs.values())) > 1:
            out["disagreements"].append({"id": i, "text": next(by_person[p][i][1] for p in labs), "labels": labs})
            for lab in set(labs.values()):
                wrong[lab] += 1
    out["per_class_disagreements"] = dict(wrong.most_common())
    ks = [v["kappa"] for v in out["pairs"].values() if v["kappa"] == v["kappa"]]
    out["mean_pairwise_kappa"] = round(sum(ks) / len(ks), 3) if ks else None
    return out


def agreement_incl_skip(by_person: dict[str, dict[str, tuple[str, str]]]) -> dict:
    """Agreement counting `skip` as a label in its own right, and listing EVERY item the labellers split on.

    `agreement` above sets skips aside (a person skipping a row is not a vote); but when comparing independent
    labellers, 'one said skip, the other said benign' is exactly the kind of disagreement we need to see."""
    people = [p for p, rows in by_person.items() if rows]
    out: dict = {"people": people, "pairs": {}, "disagreements": []}
    for p, q in itertools.combinations(people, 2):
        both = sorted(set(by_person[p]) & set(by_person[q]))
        if not both:
            continue
        la, lb = [by_person[p][i][0] for i in both], [by_person[q][i][0] for i in both]
        out["pairs"][f"{p}~{q}"] = {"n": len(both), "agree": round(sum(x == y for x, y in zip(la, lb)) / len(both), 3),
                                    "kappa": round(cohen_kappa(la, lb), 3)}
    ids = sorted({i for p in people for i in by_person[p]})
    for i in ids:
        labs = {p: by_person[p][i][0] for p in people if i in by_person[p]}
        if len(labs) >= 2 and len(set(labs.values())) > 1:
            out["disagreements"].append({"id": i, "text": next(by_person[p][i][1] for p in labs), "labels": labs})
    out["split_between"] = dict(Counter(tuple(sorted(set(d["labels"].values()))) for d in out["disagreements"]))
    return out


def interpret_kappa(k: float | None) -> str:
    """Landis and Koch's widely used wording."""
    if k is None or k != k:
        return "not enough overlapping items to say"
    for floor, word in ((0.81, "almost perfect"), (0.61, "substantial"), (0.41, "moderate"), (0.21, "fair"), (0.0, "slight")):
        if k >= floor:
            return word
    return "worse than chance"


# ---------------- reading answers back from a model or a person ----------------

_NUM_LABEL = re.compile(r"^\W*?(\d{1,4})\W+(.*)$")
_SPLIT = re.compile(r"\s+[-–—]\s+|[\t,|:(\[]")


def normalise_label(raw: str) -> str | None:
    """Turn what somebody wrote into one of the exact labels, or None. Aliases are explicit; nothing is guessed."""
    from .policy import ALIASES

    t = re.sub(r"[`*\"'.]", "", raw or "").strip().lower().replace("-", "_")
    t = re.sub(r"\s+", "_", t).strip("_")
    if t in LABELS or t == SKIP:
        return t
    return ALIASES.get(t)


def parse_answers(text: str) -> tuple[dict[int, tuple[str, int]], list[str]]:
    """Read lines like '12: benign', '12<TAB>benign<TAB>1', '| 12 | benign |' or '**12.** Skip (APT report)'.

    Forgiving about formatting (weaker models decorate their answers), strict about the label itself: a word that is not
    a label or a known alias is reported as a problem rather than guessed. Returns ({number: (label, unsure)}, problems).
    """
    out: dict[int, tuple[str, int]] = {}
    problems: list[str] = []
    for line in (text or "").splitlines():
        m = _NUM_LABEL.match(line.strip())
        if not m:
            continue  # prose, headings, blank lines
        n, rest = int(m.group(1)), m.group(2)
        label = normalise_label(_SPLIT.split(rest.strip().strip("|").strip(), 1)[0])
        if label is None:
            problems.append(f"item {n}: '{rest.strip()[:40]}' is not a label")
            continue
        flag = re.search(r"[\t,|]\s*([01])\s*\|?\s*$", rest)
        if n in out and out[n][0] != label:
            problems.append(f"item {n}: answered both '{out[n][0]}' and '{label}'; kept the first")
            continue
        out.setdefault(n, (label, int(flag.group(1)) if flag else 0))
    return out, problems


def agreed_set(by_person: dict[str, dict[str, tuple[str, str]]], min_labellers: int = 2) -> list[dict]:
    """Items that EVERY labeller who saw them labelled the same way (skip counts as a label). With several independent
    labellers this is a much stricter and more trustworthy set than any one labeller's output."""
    labs: dict[str, dict[str, str]] = defaultdict(dict)
    texts: dict[str, str] = {}
    for p, rows in by_person.items():
        for i, (lab, text) in rows.items():
            labs[i][p] = lab
            texts[i] = text
    out = []
    for i, votes in sorted(labs.items()):
        if len(votes) >= min_labellers and len(set(votes.values())) == 1:
            out.append({"id": i, "text": texts[i], "label": next(iter(votes.values())), "labellers": len(votes)})
    return out


# ---------------- validating machine-assisted ("silver") labels against a human ----------------

def stratified_sample(rows: list[dict], n: int, seed: int = 5) -> list[dict]:
    """Pick about `n` rows spread across the labels, taking ALL of a rare label before filling from common ones, so a
    short human check still covers the classes that matter (a plain random 50 would be nearly all 'benign')."""
    rng = random.Random(seed)
    by_label: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_label[r["label"]].append(r)
    for group in by_label.values():
        rng.shuffle(group)
    chosen: list[dict] = []
    pools = {k: list(v) for k, v in sorted(by_label.items())}
    while len(chosen) < min(n, len(rows)) and any(pools.values()):
        for k in list(pools):  # round-robin across labels
            if pools[k] and len(chosen) < n:
                chosen.append(pools[k].pop())
    rng.shuffle(chosen)
    return chosen


def compare(human: dict[str, tuple[str, str]], silver: dict[str, str]) -> dict:
    """How far to trust the silver labels: agreement between one human and the machine-assisted labels."""
    ids = sorted(i for i in human if i in silver)
    out: dict = {"n": len(ids)}
    if not ids:
        return out
    h, s = [human[i][0] for i in ids], [silver[i] for i in ids]
    out["agree"] = round(sum(a == b for a, b in zip(h, s)) / len(ids), 3)
    out["kappa"] = round(cohen_kappa(h, s), 3)
    keep = [k for k in range(len(ids)) if h[k] != SKIP and s[k] != SKIP]
    if len(keep) >= 2:
        out["agree_excluding_skip"] = round(sum(h[k] == s[k] for k in keep) / len(keep), 3)
        out["kappa_excluding_skip"] = round(cohen_kappa([h[k] for k in keep], [s[k] for k in keep]), 3)
    # per class: of the items the machine called X, how many did the human also call X?
    per: dict = {}
    for lab in sorted(set(s)):
        idx = [k for k in range(len(ids)) if s[k] == lab]
        per[lab] = {"machine_called_it": len(idx), "human_agreed": sum(h[k] == lab for k in idx)}
    out["per_machine_label"] = per
    out["disagreements"] = [{"id": ids[k], "human": h[k], "silver": s[k], "text": human[ids[k]][1]}
                            for k in range(len(ids)) if h[k] != s[k]]
    return out


# ---------------- consensus and split ----------------

def consensus(by_person: dict[str, dict[str, tuple[str, str]]], adjudicated: dict[str, str] | None = None) -> list[dict]:
    """One label per item: the adjudicated label if the team decided one, else the majority, else REVIEW."""
    adjudicated = adjudicated or {}
    labels: dict[str, list[str]] = defaultdict(list)
    texts: dict[str, str] = {}
    for rows in by_person.values():
        for i, (lab, text) in rows.items():
            texts[i] = text
            if lab != SKIP:
                labels[i].append(lab)
    out = []
    for i, labs in labels.items():
        if i in adjudicated:
            label = adjudicated[i]
        else:
            top, n = Counter(labs).most_common(1)[0]
            label = top if n > len(labs) / 2 else REVIEW
        out.append({"id": i, "text": texts[i], "label": label, "raters": len(labs)})
    return sorted(out, key=lambda r: r["id"])


def split_dev_test(rows: list[dict], test_frac: float = 0.4, seed: int = 3) -> tuple[list[dict], list[dict]]:
    """Stratified: every class is split in the same proportion, so the test set mirrors the whole."""
    rng = random.Random(seed)
    by_label: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_label[r["label"]].append(r)
    dev, test = [], []
    for label in sorted(by_label):
        group = sorted(by_label[label], key=lambda r: r["id"])
        rng.shuffle(group)
        k = round(len(group) * test_frac) if len(group) >= 2 else 0
        test += group[:k]
        dev += group[k:]
    return sorted(dev, key=lambda r: r["id"]), sorted(test, key=lambda r: r["id"])


def write_labelled(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "id"])
        for r in rows:
            w.writerow([r["text"], r["label"], r["id"]])
