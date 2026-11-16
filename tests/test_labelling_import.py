"""Reading answers back from another labeller (a model or a person), and comparing several independent labellers."""
import csv

import pytest

from darklens.labelling import cli
from darklens.labelling import workflow as wf


# ---------------- normalising a label word ----------------

@pytest.mark.parametrize("raw,expected", [
    ("benign", "benign"), ("Benign", "benign"), (" BENIGN. ", "benign"), ("**benign**", "benign"), ("`skip`", "skip"),
    ("ransomware_leak", "ransomware_leak"), ("Ransomware Leak", "ransomware_leak"), ("ransomware-leak", "ransomware_leak"),
    ("ransomware", "ransomware_leak"), ("breach", "credential_dump"), ("Data breach", "credential_dump"),
    ("phishing", "phishing_kit"), ("other", "skip"), ("Unclear", "skip"), ("not sure", "skip"),
])
def test_known_spellings_and_aliases_become_the_exact_label(raw, expected):
    assert wf.normalise_label(raw) == expected


@pytest.mark.parametrize("raw", ["", None, "malicious", "very bad", "spam", "123", "ransomware_leak_or_credential"])
def test_unknown_words_are_rejected_not_guessed(raw):
    assert wf.normalise_label(raw) is None


# ---------------- parsing a messy answer ----------------

def test_the_requested_formats_parse():
    got, problems = wf.parse_answers("1: benign\n2: skip\n3\tcredential_dump\t1\n4. ransomware_leak\n5) phishing_kit")
    assert got == {1: ("benign", 0), 2: ("skip", 0), 3: ("credential_dump", 1), 4: ("ransomware_leak", 0), 5: ("phishing_kit", 0)}
    assert problems == []


def test_decorated_answers_from_a_chatty_model_still_parse():
    reply = """Sure! Here are my labels:

| # | label |
|---|---|
| 1 | benign |
| 2 | **skip** |

**3.** credential_dump (breach of customer data)
4 - benign - ordinary news
5: Skip, because it is an APT report
- 6: benign
Let me know if you want me to explain any of these!"""
    got, problems = wf.parse_answers(reply)
    assert got == {1: ("benign", 0), 2: ("skip", 0), 3: ("credential_dump", 0), 4: ("benign", 0), 5: ("skip", 0), 6: ("benign", 0)}
    assert problems == []


def test_prose_blank_lines_and_headings_are_ignored():
    got, problems = wf.parse_answers("Batch 2\n\nHere you go\n\n7: benign\n\nThanks!")
    assert got == {7: ("benign", 0)} and problems == []


def test_a_bad_label_is_reported_with_its_item_number():
    got, problems = wf.parse_answers("1: benign\n2: dangerous\n3: skip")
    assert got == {1: ("benign", 0), 3: ("skip", 0)} and len(problems) == 1 and "item 2" in problems[0]


def test_a_contradiction_keeps_the_first_answer_and_says_so():
    got, problems = wf.parse_answers("1: benign\n1: skip\n2: benign\n2: benign")
    assert got[1] == ("benign", 0) and got[2] == ("benign", 0) and len(problems) == 1 and "item 1" in problems[0]


def test_empty_and_none_input():
    assert wf.parse_answers("") == ({}, []) and wf.parse_answers(None) == ({}, [])


# ---------------- comparing several independent labellers ----------------

def _people():
    mk = lambda d: {i: (lab, f"text {i}") for i, lab in d.items()}  # noqa: E731
    return {"a": mk({"1": "benign", "2": "skip", "3": "benign", "4": "credential_dump"}),
            "b": mk({"1": "benign", "2": "benign", "3": "benign", "4": "credential_dump"}),
            "c": mk({"1": "benign", "2": "skip", "3": "benign", "4": "ransomware_leak"})}


def test_agreement_incl_skip_sees_the_skip_versus_benign_splits_that_the_plain_version_hides():
    plain = wf.agreement(_people())
    full = wf.agreement_incl_skip(_people())
    assert "2" not in {d["id"] for d in plain["disagreements"]}  # the plain version sets skips aside
    assert {d["id"] for d in full["disagreements"]} == {"2", "4"}
    assert full["pairs"]["a~b"]["agree"] == 0.75 and full["pairs"]["a~c"]["agree"] == 0.75
    assert full["split_between"][("benign", "skip")] == 1 and full["split_between"][("credential_dump", "ransomware_leak")] == 1


def test_agreed_set_needs_everyone_to_agree_and_counts_skip_as_a_label():
    agreed = {r["id"]: r for r in wf.agreed_set(_people(), min_labellers=3)}
    assert set(agreed) == {"1", "3"} and agreed["1"]["label"] == "benign" and agreed["1"]["labellers"] == 3
    two = {r["id"] for r in wf.agreed_set({"a": _people()["a"], "b": _people()["b"]}, 2)}
    assert two == {"1", "3", "4"}
    assert wf.agreed_set({"a": _people()["a"]}, 2) == []  # one labeller cannot "agree"


def test_agreement_with_nothing_in_common_is_empty():
    assert wf.agreement_incl_skip({"a": {"1": ("benign", "t")}, "b": {"2": ("benign", "t")}})["pairs"] == {}


# ---------------- the command-line flow ----------------

def _items(base, n=6):
    (base / "silver").mkdir(parents=True)
    with open(base / "silver" / "items.txt", "w", encoding="utf-8") as f:
        for k in range(1, n + 1):
            f.write(f"{k}\tid{k}\tstory number {k} about something\n")


def test_pack_writes_numbered_copy_paste_batches_with_the_prompt(tmp_path, capsys):
    base = tmp_path / "lab"
    _items(base, 7)
    assert cli.run(["pack", "--size", "3", "--dir", str(base)]) == 0
    files = sorted((base / "pack").glob("batch-*.txt"))
    assert [f.name for f in files] == ["batch-01.txt", "batch-02.txt", "batch-03.txt"]
    first = files[0].read_text(encoding="utf-8")
    assert "STEP 1" in first and "1. story number 1" in first and "3. story number 3" in first and "4. story" not in first
    assert "7. story number 7" in files[2].read_text(encoding="utf-8")  # numbers stay global so batches merge
    assert "label import" in (base / "pack" / "HOW-TO.txt").read_text(encoding="utf-8")


def test_import_maps_numbers_to_ids_and_reports_what_is_missing(tmp_path, capsys):
    base = tmp_path / "lab"
    _items(base, 5)
    ans = tmp_path / "answers.txt"
    ans.write_text("Batch 1\n1: benign\n2: skip\n3: nonsense\n5: credential_dump\n99: benign\n", encoding="utf-8")
    assert cli.run(["import", "gpt", str(ans), "--dir", str(base)]) == 1  # not complete, so it says so
    out = capsys.readouterr().out
    assert "MISSING 2" in out and "[3, 4]" in out and "not a label" in out and "not in the item list" in out
    rows = list(csv.DictReader(open(base / "silver" / "gpt.csv", newline="", encoding="utf-8")))
    assert [(r["id"], r["label"]) for r in rows] == [("id1", "benign"), ("id2", "skip"), ("id5", "credential_dump")]
    more = tmp_path / "more.txt"
    more.write_text("3: benign\n4: benign\n", encoding="utf-8")
    assert cli.run(["import", "gpt", str(ans), str(more), "--dir", str(base)]) == 1  # item 3 is still 'nonsense' in the first file
    ans.write_text("1: benign\n2: skip\n5: credential_dump\n", encoding="utf-8")
    assert cli.run(["import", "gpt", str(ans), str(more), "--dir", str(base)]) == 0  # several files merge into one answer set


@pytest.mark.parametrize("argv", [["import"], ["import", "x"], ["pack"], ["agree"]])
def test_new_commands_give_help_not_a_crash(argv, tmp_path, capsys):
    assert cli.run(argv + ["--dir", str(tmp_path / "empty")]) == 1 and capsys.readouterr().out


def test_agree_end_to_end_ignores_its_own_output_files(tmp_path, capsys):
    base = tmp_path / "lab"
    _items(base, 6)

    def write(name, labels):
        with open(base / "silver" / f"{name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "label", "text", "unsure"])
            for k, lab in enumerate(labels, 1):
                w.writerow([f"id{k}", lab, f"story number {k}", 0])
    write("one", ["benign"] * 5 + ["credential_dump"])
    write("two", ["benign"] * 4 + ["skip", "credential_dump"])
    assert cli.run(["agree", "--dir", str(base)]) == 0
    out = capsys.readouterr().out
    assert "labellers: one, two" in out and "items ALL labellers agree on: 5" in out and "benign vs skip" in out
    assert cli.run(["agree", "--dir", str(base)]) == 0  # a second run must not read agreed.csv / contested.csv as labellers
    assert "labellers: one, two" in capsys.readouterr().out
    assert len(list(csv.DictReader(open(base / "silver" / "contested.csv", encoding="utf-8")))) == 1
    write("three", ["benign"] * 4 + ["benign", "credential_dump"])
    assert cli.run(["agree", "--dir", str(base)]) == 0
    out = capsys.readouterr().out
    assert "Fleiss" in out and "items ALL labellers agree on: 5" in out
