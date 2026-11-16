"""`python -m darklens label ...`: pool, sheets, check, split, validate, pack, import, agree."""
from __future__ import annotations

import csv
from collections import Counter
from datetime import date
from pathlib import Path

from . import sources, workflow as wf

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "labelling"


def _opt(argv: list[str], name: str, default=None):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default


def hint_class(text: str) -> str:
    """A cheap guess at the class, used only to find rare classes when sampling. Never shown to labellers."""
    from ..nlp.classifier import get_classifier
    from ..rules.engine import run_rules

    hits = run_rules(text)
    if hits:
        best = max(hits, key=lambda h: h[1].score)
        return best[0].category
    cat, conf, _ = get_classifier().classify(text)
    return cat if conf >= 0.3 else "benign"


def _load_candidates(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        return {r["id"]: r for r in csv.DictReader(f)}


def _save_candidates(path: Path, rows: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "text", "source", "kind", "fetched"])
        for r in rows.values():
            w.writerow([r["id"], r["text"], r["source"], r["kind"], r.get("fetched", "")])


def cmd_pool(argv: list[str], base: Path, fetch=None, _today=None) -> int:
    """Add public text to the candidate pool. The pool GROWS across runs, so a few days of fetching builds a real
    spread; run it daily. `--add FILE.csv` adds your own public examples (a `text` column, optional `source`)."""
    path = base / "candidates.csv"
    pool = _load_candidates(path)
    before = len(pool)
    extra = _opt(argv, "--add")
    if extra:
        with open(extra, newline="", encoding="utf-8-sig") as f:
            added = [{"text": sources.clean(r.get("text"), 400), "source": r.get("source") or "added-by-hand", "kind": "security"}
                     for r in csv.DictReader(f)]
        items, report = [it for it in added if len(it["text"]) >= 20], {"added-file": len(added)}
        for it in items:
            it["id"] = sources.text_id(it["text"])
    else:
        items, report = (fetch or sources.fetch_all)()
    print("sources:", report)
    if not items:
        print("Nothing could be fetched. Check your internet connection and try again.")
        return 1
    today = (_today or date.today)().isoformat()
    for it in items:
        it.setdefault("fetched", today)  # when WE first saw it: lets a later test set exclude everything already tuned on
        pool.setdefault(it["id"], it)
    _save_candidates(path, pool)
    kinds = Counter(r["kind"] for r in pool.values())
    print(f"candidate pool: {before} -> {len(pool)} texts ({dict(kinds)}) at {path}")
    print("Run this again on other days: feeds only show their latest items, so the pool grows over time.")
    return 0


def cmd_sheets(argv: list[str], base: Path) -> int:
    names = [n.strip() for n in (argv[0] if argv else "").split(",") if n.strip()]
    if not names:
        print("Give the labellers' names: label sheets bhavit,krish,naisha,prateek,sahil")
        return 1
    candidates = _load_candidates(base / "candidates.csv")
    if not candidates:
        print("No candidates yet. Run: python -m darklens label pool")
        return 1
    since = _opt(argv, "--since")
    if since:
        # An untouched test set: only items we first saw on/after this date, never ones already used for tuning.
        candidates = {i: r for i, r in candidates.items() if (r.get("fetched") or "") >= since}
        if not candidates:
            print(f"No candidates were fetched on or after {since}. Run `label pool` on a later day first.")
            return 1
    per_class = int(_opt(argv, "--per-class", 30))
    items, info = wf.select(list(candidates.values()), hint_class, total=int(_opt(argv, "--total", 300)), per_class=per_class)
    short = {c: n for c, n in info["candidates_per_class"].items() if n < per_class}
    print(f"selected {len(items)} of {info['pool']} candidates.")
    print(f"classes with fewer than {per_class} likely candidates (add examples with `label pool --add FILE`):", short or "none")
    shared = int(_opt(argv, "--shared", 40))
    out = wf.assign(items, names, shared=shared)
    for n, rows in out.items():
        wf.write_sheet(base / "sheets" / f"{n}.csv", rows)
        print(f"{n}: {len(rows)} items -> {base / 'sheets' / (n + '.csv')}")
    print(f"{min(shared, len(items)) if len(names) > 1 else 0} items are shared by everyone, for the agreement check.")
    print("Send each person ONLY their own file. Nobody should see the others' labels or the model's guesses.")
    return 0


def cmd_check(argv: list[str], base: Path) -> int:
    by_person, problems, prog = wf.collect(base / "sheets")
    if not by_person:
        print("No sheets found. Run: python -m darklens label sheets <names>")
        return 1
    print("progress:", {p: f"{d}/{t}" for p, (d, t) in prog.items()})
    for p in problems:
        print("PROBLEM:", p)
    ag = wf.agreement(by_person)
    print(f"items labelled by 2 or more people: {ag['shared_items']}")
    for pair, v in ag["pairs"].items():
        print(f"  {pair}: agree {v['agree']:.0%} on {v['n']} items, kappa {v['kappa']}")
    if "fleiss_kappa" in ag:
        print(f"overall agreement (Fleiss kappa) on the {ag['items_labelled_by_everyone']} items everyone labelled: "
              f"{ag['fleiss_kappa']} ({wf.interpret_kappa(ag['fleiss_kappa'])})")
    if ag.get("per_class_disagreements"):
        print("classes involved in disagreements:", ag["per_class_disagreements"])
    if ag["disagreements"]:
        out = base / "final" / "disagreements.csv"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "text", "labels", "decided_label"])
            for d in ag["disagreements"]:
                w.writerow([d["id"], d["text"], "; ".join(f"{p}={lab}" for p, lab in d["labels"].items()), ""])
        print(f"{len(ag['disagreements'])} disagreements to discuss -> {out} (fill the last column, then use it in `label split --adjudicated`)")
    return 1 if problems else 0


def cmd_split(argv: list[str], base: Path) -> int:
    by_person, problems, _ = wf.collect(base / "sheets")
    if problems:
        print("Fix these first:\n  " + "\n  ".join(problems))
        return 1
    adjudicated: dict[str, str] = {}
    adj = _opt(argv, "--adjudicated")
    if adj:
        with open(adj, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                lab = (r.get("decided_label") or "").strip().lower().replace(" ", "_")
                if lab:
                    if lab not in wf.LABELS:
                        print(f"Unknown decided_label '{lab}' for item {r['id']}")
                        return 1
                    adjudicated[r["id"]] = lab
    rows = wf.consensus(by_person, adjudicated)
    undecided = [r for r in rows if r["label"] == wf.REVIEW]
    if undecided:
        print(f"{len(undecided)} items have no majority. Discuss them (see `label check`) and pass --adjudicated.")
        return 1
    dev, test = wf.split_dev_test(rows, test_frac=float(_opt(argv, "--test-frac", 0.4)))
    out = base / "final"
    wf.write_labelled(out / "all.csv", rows)
    wf.write_labelled(out / "dev.csv", dev)
    wf.write_labelled(out / "test.csv", test)
    print(f"{len(rows)} labelled items -> dev {len(dev)}, test {len(test)}")
    print("per class (dev / test):", {c: f"{sum(r['label'] == c for r in dev)} / {sum(r['label'] == c for r in test)}" for c in sorted({r['label'] for r in rows})})
    print("The TEST set is untouchable: do not tune rules or retrain on it. Tune on dev.csv, report on test.csv.")
    print(f"  python -m darklens eval --csv {out / 'test.csv'} --pipeline")
    return 0


def _load_silver(path: Path) -> dict[str, str]:
    with open(path, newline="", encoding="utf-8") as f:
        return {r["id"]: r["label"] for r in csv.DictReader(f)}


def cmd_validate(argv: list[str], base: Path) -> int:
    """Check how far machine-assisted ("silver") labels can be trusted, using one human's judgement on a sample.

      label validate make NAME [--n 50]   write a short sheet of items the machine labelled, for a human to label blind
      label validate check NAME           compare that human's labels with the machine's
    """
    if len(argv) < 2 or argv[0] not in ("make", "check"):
        print(cmd_validate.__doc__)
        return 1
    mode, name = argv[0], argv[1]
    silver_path = Path(_opt(argv, "--silver", base / "silver" / "llm.csv"))
    sheet = base / "validation" / f"{name}.csv"
    if not silver_path.exists():
        print(f"No silver labels at {silver_path}")
        return 1
    if mode == "make":
        with open(silver_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        picked = wf.stratified_sample(rows, int(_opt(argv, "--n", 50)))
        wf.write_sheet(sheet, [{"id": r["id"], "text": r["text"]} for r in picked])
        print(f"{len(picked)} items for {name} -> {sheet}")
        print("Label blind (the machine's labels are not in the sheet). Same label values as the guide; use `skip` for attack or exploitation news that fits no class.")
        print(f"Then run: python -m darklens label validate check {name}")
        return 0
    if not sheet.exists():
        print(f"No sheet at {sheet}. Run `label validate make {name}` first.")
        return 1
    human, problems = wf.read_sheet(sheet)
    for p in problems:
        print("PROBLEM:", p)
    done, total = wf.progress(sheet)
    print(f"{name} has labelled {done} of {total} items")
    res = wf.compare(human, _load_silver(silver_path))
    if not res.get("n"):
        print("Nothing to compare yet.")
        return 1
    print(f"overlap {res['n']} items: agree {res['agree']:.0%}, kappa {res['kappa']} ({wf.interpret_kappa(res['kappa'])})")
    if "kappa_excluding_skip" in res:
        print(f"ignoring items either side called 'skip': agree {res['agree_excluding_skip']:.0%}, kappa {res['kappa_excluding_skip']} ({wf.interpret_kappa(res['kappa_excluding_skip'])})")
    for lab, v in res["per_machine_label"].items():
        print(f"  machine said {lab}: human agreed on {v['human_agreed']} of {v['machine_called_it']}")
    out = base / "validation" / f"{name}-disagreements.csv"
    if res["disagreements"]:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "human", "machine", "text"])
            for d in res["disagreements"]:
                w.writerow([d["id"], d["human"], d["silver"], d["text"]])
        print(f"{len(res['disagreements'])} disagreements -> {out}")
    return 0


def _numbered_items(base: Path) -> dict[int, tuple[str, str]]:
    path = base / "silver" / "items.txt"
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            out[int(parts[0])] = (parts[1], parts[2])
    return out


def cmd_pack(argv: list[str], base: Path) -> int:
    """Write copy-paste batches for another labeller (for example a chatbot): `label pack [--size 25]`."""
    from .policy import SIMPLE_PROMPT

    items = _numbered_items(base)
    if not items:
        print("No numbered items at silver/items.txt.")
        return 1
    size = int(_opt(argv, "--size", 25))
    out = base / "pack"
    out.mkdir(parents=True, exist_ok=True)
    nums = sorted(items)
    files = []
    for b in range(0, len(nums), size):
        chunk = nums[b:b + size]
        body = SIMPLE_PROMPT + "\n".join(f"{n}. {items[n][1]}" for n in chunk) + "\n"
        f = out / f"batch-{b // size + 1:02d}.txt"
        f.write_text(body, encoding="utf-8")
        files.append(f.name)
    (out / "HOW-TO.txt").write_text(
        f"1. Open a NEW chat for each batch file ({len(files)} files). Paste the whole file and send it.\n"
        "2. Copy the model's answer (lines like '12: benign') and paste it at the end of answers.txt in this folder.\n"
        "   If it adds explanations or tables, that is fine, the importer ignores them.\n"
        "3. When every batch is done, run:  python -m darklens label import gpt labelling/pack/answers.txt\n"
        "   It lists any item that is missing or not a valid label; paste just those back in a small batch.\n"
        "4. Then:  python -m darklens label agree\n", encoding="utf-8")
    print(f"{len(files)} batches of up to {size} items -> {out}")
    print(f"Follow {out / 'HOW-TO.txt'}")
    return 0


def cmd_import(argv: list[str], base: Path) -> int:
    """`label import NAME FILE...`: read another labeller's answers (numbered lines) into silver/NAME.csv."""
    if len(argv) < 2:
        print(cmd_import.__doc__)
        return 1
    name, files = argv[0], [a for a in argv[1:] if not a.startswith("--")]
    items = _numbered_items(base)
    if not items:
        print("No numbered items at silver/items.txt.")
        return 1
    text = ""
    for f in files:
        p = Path(f)
        if not p.exists():
            print(f"Cannot find {f}")
            return 1
        text += p.read_text(encoding="utf-8", errors="replace") + "\n"
    answers, problems = wf.parse_answers(text)
    unknown = sorted(n for n in answers if n not in items)
    missing = sorted(set(items) - set(answers))
    for p in problems[:15]:
        print("PROBLEM:", p)
    if unknown:
        print(f"Ignored numbers that are not in the item list: {unknown[:10]}")
    out = base / "silver" / f"{name}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "label", "text", "unsure"])
        for n in sorted(n for n in answers if n in items):
            i, t = items[n]
            w.writerow([i, answers[n][0], t, answers[n][1]])
    got = Counter(a[0] for n, a in answers.items() if n in items)
    print(f"{name}: {sum(got.values())} of {len(items)} items -> {out}")
    print("counts:", dict(got))
    if missing:
        print(f"MISSING {len(missing)} items (paste only these back in): {missing[:40]}{' ...' if len(missing) > 40 else ''}")
    return 1 if (missing or problems) else 0


def cmd_agree(argv: list[str], base: Path) -> int:
    """`label agree`: how much the independent labellers agree, and the set they ALL agree on."""
    by_person: dict[str, dict[str, tuple[str, str]]] = {}
    for p in sorted((base / "silver").glob("*.csv")):
        if p.stem in ("agreed", "contested"):
            continue  # this command's own output files are not labellers
        with open(p, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not {"id", "label", "text"} <= set(reader.fieldnames or []):
                continue
            by_person[p.stem] = {r["id"]: (r["label"], r["text"]) for r in reader}
    if len(by_person) < 2:
        print("Need at least two labellers in silver/ (import another with `label import`).")
        return 1
    ag = wf.agreement_incl_skip(by_person)
    print(f"labellers: {', '.join(by_person)}")
    for pair, v in ag["pairs"].items():
        print(f"  {pair} (every item, skip counted as a label): agree {v['agree']:.0%} on {v['n']} items, kappa {v['kappa']} ({wf.interpret_kappa(v['kappa'])})")
    # the same, with `skip` set aside, because 'skip' is the fuzzy edge of the policy
    ns = {p: {i: lt for i, lt in rows.items() if lt[0] != wf.SKIP} for p, rows in by_person.items()}
    ag2 = wf.agreement(ns)
    for pair, v in ag2["pairs"].items():
        print(f"  {pair} (only items nobody skipped): agree {v['agree']:.0%} on {v['n']} items, kappa {v['kappa']} ({wf.interpret_kappa(v['kappa'])})")
    if len(by_person) >= 2:
        full = {i for i in set.intersection(*[set(r) for r in by_person.values()])}
        if full:
            f = wf.fleiss_kappa([[by_person[p][i][0] for p in by_person] for i in sorted(full)])
            print(f"overall (Fleiss kappa, {len(by_person)} labellers, {len(full)} items): {round(f, 3)} ({wf.interpret_kappa(f)})")
    ag["per_class_disagreements"] = dict(Counter(lab for d in ag["disagreements"] for lab in set(d["labels"].values())).most_common())
    if ag["split_between"]:
        print("what they split on:", {" vs ".join(k): v for k, v in ag["split_between"].items()})
    agreed = wf.agreed_set(by_person, min_labellers=len(by_person))
    out = base / "silver" / "agreed.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "label", "text", "labellers"])
        for r in agreed:
            w.writerow([r["id"], r["label"], r["text"], r["labellers"]])
    print(f"items ALL labellers agree on: {len(agreed)} -> {out}  {dict(Counter(r['label'] for r in agreed))}")
    contested = base / "silver" / "contested.csv"
    with open(contested, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "text", "labels"])
        for d in ag["disagreements"]:
            w.writerow([d["id"], d["text"], "; ".join(f"{p}={lab}" for p, lab in d["labels"].items())])
    print(f"{len(ag['disagreements'])} contested items -> {contested}")
    if ag["per_class_disagreements"]:
        print("labels involved in disagreements:", ag["per_class_disagreements"])
    print(f"score DarkLens on the agreed items:  python -m darklens eval --csv {out} --pipeline")
    return 0


def run(argv: list[str], fetch=None, _today=None) -> int:
    if not argv or argv[0] not in ("pool", "sheets", "check", "split", "validate", "pack", "import", "agree"):
        print(__doc__)
        return 1
    base = Path(_opt(argv, "--dir", DEFAULT_DIR))
    cmd, rest = argv[0], argv[1:]
    if "--dir" in rest:  # the folder option is not a file name for commands that take file lists
        k = rest.index("--dir")
        rest = rest[:k] + rest[k + 2:]
    return {"pool": lambda: cmd_pool(rest, base, fetch, _today), "sheets": lambda: cmd_sheets(rest, base),
            "check": lambda: cmd_check(rest, base), "split": lambda: cmd_split(rest, base),
            "validate": lambda: cmd_validate(rest, base), "pack": lambda: cmd_pack(rest, base),
            "import": lambda: cmd_import(rest, base), "agree": lambda: cmd_agree(rest, base)}[cmd]()
