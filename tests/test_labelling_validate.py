"""Validating machine-assisted ("silver") labels against a human, and keeping a later test set untouched."""
import csv
from datetime import date

import pytest

from darklens.labelling import cli, sources
from darklens.labelling import workflow as wf
from darklens.nlp import realeval


def _silver_rows():
    labels = ["benign"] * 40 + ["skip"] * 10 + ["credential_dump"] * 4 + ["ransomware_leak"] * 3 + ["phishing_kit"]
    return [{"id": f"s{i}", "text": f"text {i}", "label": lab} for i, lab in enumerate(labels)]


def _write_silver(base):
    (base / "silver").mkdir(parents=True)
    with open(base / "silver" / "llm.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "label", "text"])
        for r in _silver_rows():
            w.writerow([r["id"], r["label"], r["text"]])


def test_stratified_sample_includes_every_rare_class_before_filling_with_common_ones():
    picked = wf.stratified_sample(_silver_rows(), 20)
    labels = [r["label"] for r in picked]
    assert len(picked) == 20 and labels.count("phishing_kit") == 1 and labels.count("ransomware_leak") == 3
    assert labels.count("credential_dump") == 4  # all the rare ones are in; only the common ones are thinned
    assert labels.count("benign") + labels.count("skip") == 12


def test_stratified_sample_copes_with_asking_for_more_than_exists_and_is_deterministic():
    rows = _silver_rows()
    assert len(wf.stratified_sample(rows, 999)) == len(rows)
    assert [r["id"] for r in wf.stratified_sample(rows, 15, seed=2)] == [r["id"] for r in wf.stratified_sample(rows, 15, seed=2)]
    assert wf.stratified_sample([], 10) == []


def test_compare_reports_agreement_kappa_skip_handling_and_disagreements():
    silver = {"1": "benign", "2": "benign", "3": "credential_dump", "4": "skip", "5": "ransomware_leak", "6": "benign"}
    chosen = {"1": "benign", "2": "benign", "3": "credential_dump", "4": "benign", "5": "credential_dump", "6": "benign"}
    human = {i: (lab, f"t{i}") for i, lab in chosen.items()}
    r = wf.compare(human, silver)
    assert r["n"] == 6 and r["agree"] == round(4 / 6, 3)
    assert r["agree_excluding_skip"] == round(4 / 5, 3)  # the item the machine called 'skip' is set aside
    assert {d["id"] for d in r["disagreements"]} == {"4", "5"}
    assert r["per_machine_label"]["ransomware_leak"] == {"machine_called_it": 1, "human_agreed": 0}
    assert wf.compare({}, silver) == {"n": 0}
    assert wf.compare({"x": ("benign", "t")}, silver)["n"] == 0  # no overlap


def test_validate_make_and_check_end_to_end(tmp_path, capsys):
    base = tmp_path / "lab"
    _write_silver(base)
    assert cli.run(["validate", "make", "ann", "--n", "20", "--dir", str(base)]) == 0
    sheet = base / "validation" / "ann.csv"
    text = sheet.read_text(encoding="utf-8-sig")
    assert text.splitlines()[0] == "id,text,label,notes"
    assert len(text.splitlines()) == 21  # header + 20 items
    assert "credential_dump" not in text and "phishing_kit" not in text  # blind: the machine's labels are not in the sheet
    assert cli.run(["validate", "check", "ann", "--dir", str(base)]) == 1  # nothing labelled yet
    silver = {r["id"]: r["label"] for r in _silver_rows()}
    rows = list(csv.DictReader(open(sheet, newline="", encoding="utf-8-sig")))
    with open(sheet, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["id", "text", "label", "notes"])
        for k, r in enumerate(rows):
            w.writerow([r["id"], r["text"], "benign" if k == 0 else silver[r["id"]], ""])
    capsys.readouterr()
    assert cli.run(["validate", "check", "ann", "--dir", str(base)]) == 0
    out = capsys.readouterr().out
    assert "labelled 20 of 20" in out and "kappa" in out and "machine said" in out


@pytest.mark.parametrize("argv", [["validate"], ["validate", "make"], ["validate", "nonsense", "x"]])
def test_validate_gives_help_not_a_crash(argv, tmp_path, capsys):
    assert cli.run(argv + ["--dir", str(tmp_path)]) == 1 and capsys.readouterr().out


def test_validate_without_silver_labels_says_so(tmp_path, capsys):
    assert cli.run(["validate", "make", "x", "--dir", str(tmp_path)]) == 1 and "No silver labels" in capsys.readouterr().out


def _fetch_once():
    items = [{"id": sources.text_id(f"ordinary sentence number {i} about nothing"), "text": f"ordinary sentence number {i} about nothing",
              "source": "fake", "kind": "general"} for i in range(8)]
    return items, {"fake": len(items)}


def test_pool_records_when_each_item_was_first_seen_and_since_excludes_older_ones(tmp_path, capsys):
    base = str(tmp_path / "lab")
    assert cli.run(["pool", "--dir", base], fetch=_fetch_once, _today=lambda: date(2026, 11, 16)) == 0

    def later():
        items, rep = _fetch_once()
        text = "a brand new story about a ransomware gang"
        items.append({"id": sources.text_id(text), "text": text, "source": "fake", "kind": "security"})
        return items, rep

    assert cli.run(["pool", "--dir", base], fetch=later, _today=lambda: date(2026, 11, 20)) == 0
    rows = list(csv.DictReader(open(tmp_path / "lab" / "candidates.csv", encoding="utf-8")))
    assert {r["fetched"] for r in rows} == {"2026-11-16", "2026-11-20"}
    assert sum(r["fetched"] == "2026-11-20" for r in rows) == 1  # only the genuinely new item carries the new date
    assert cli.run(["sheets", "ann", "--dir", base, "--since", "2026-11-20", "--total", "5"]) == 0
    sheet_rows = list(csv.DictReader(open(tmp_path / "lab" / "sheets" / "ann.csv", encoding="utf-8-sig")))
    assert [r["text"] for r in sheet_rows] == ["a brand new story about a ransomware gang"]
    capsys.readouterr()
    assert cli.run(["sheets", "ann", "--dir", base, "--since", "2030-01-01"]) == 1 and "on or after" in capsys.readouterr().out


def test_skip_rows_are_left_out_of_evaluation_files(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("text,label\nFirst text,benign\nSecond text,skip\nThird text,ransomware_leak\n", encoding="utf-8")
    assert realeval.load_csv(str(p)) == (["First text", "Third text"], ["benign", "ransomware_leak"])
