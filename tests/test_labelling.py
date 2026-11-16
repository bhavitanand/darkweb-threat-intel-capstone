"""The labelling toolkit: feed parsing, sampling, sheets, agreement statistics, consensus, split and the CLI flow."""
import csv
import math

import pytest

from darklens import pipeline
from darklens.labelling import cli, sources
from darklens.labelling import workflow as wf
from darklens.nlp import realeval
from darklens.nlp.classifier import get_classifier

RSS = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Hackers &amp; leak sites: data stolen</title><description>&lt;p&gt;A &lt;b&gt;ransomware&lt;/b&gt; gang posted 2 TB.&lt;/p&gt;</description></item>
<item><title>Second story about phishing kits</title><description>Second story about phishing kits are sold cheaply.</description></item>
<item><title></title><description>no title so skipped</description></item>
</channel></rss>"""

ATOM = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>An atom entry about exploits</title><summary>Selling a zero-day.</summary></entry></feed>"""


# ---------------- feed parsing ----------------

def test_rss_is_parsed_cleaned_and_untitled_items_skipped():
    items = sources.parse_feed(RSS, "x", "security")
    assert [i["text"] for i in items] == [
        "Hackers & leak sites: data stolen. A ransomware gang posted 2 TB.",
        "Second story about phishing kits",  # a summary that only repeats the title is not appended twice
    ]
    assert all(i["source"] == "x" and i["kind"] == "security" for i in items)


def test_a_windows_1252_feed_keeps_its_apostrophes_and_dashes():
    raw = ('<?xml version="1.0" encoding="windows-1252"?><rss><channel><item><title>Microsoft’s outage — worse than CrowdStrike’s</title>'
           '<description>Governments scrambled.</description></item></channel></rss>').encode("cp1252")
    text = sources.parse_feed(raw, "x", "general")[0]["text"]
    assert "�" not in text and text.startswith("Microsoft’s outage — worse")


def test_an_unknown_declared_encoding_is_refused_not_crashed():
    assert sources.parse_feed(b'<?xml version="1.0" encoding="no-such-codec"?><rss/>', "x", "general") == []


def test_atom_is_parsed_too():
    assert sources.parse_feed(ATOM, "a", "security")[0]["text"] == "An atom entry about exploits. Selling a zero-day."


@pytest.mark.parametrize("bad", [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>',
    "<rss><channel><item><title>x", "not xml at all", "", "x" * (sources.MAX_BYTES + 1),
])
def test_hostile_or_broken_xml_returns_nothing(bad):
    assert sources.parse_feed(bad, "x", "security") == []


def test_clean_strips_markup_unescapes_and_truncates():
    assert sources.clean("<p>a&nbsp;b &lt;c&gt;</p>") == "a b <c>"
    long = sources.clean("word " * 200, 50)
    assert len(long) <= 53 and long.endswith("...")
    assert sources.clean(None) == ""


def test_text_id_ignores_case_and_spacing():
    assert sources.text_id("Hello   World") == sources.text_id("hello world")
    assert sources.text_id("a") != sources.text_id("b")


def test_hacker_news_payload():
    assert sources.parse_hn({"hits": [{"title": "A <b>nice</b> post"}, {"title": ""}, "junk", None]})[0]["text"] == "A nice post"
    assert sources.parse_hn(None) == [] and sources.parse_hn({"hits": "x"}) == []


def test_fetch_all_survives_a_failing_feed_and_dedupes():
    feeds = [("good", "u1", "security"), ("bad", "u2", "security"), ("dup", "u3", "general")]

    def get(url):
        if url == "u2":
            raise ConnectionError("down")
        if url == sources.HN_URL:
            return '{"hits": [{"title": "Hacker news title that is long enough"}]}', "application/json"
        return RSS, "application/xml"

    items, report = sources.fetch_all(get=get, feeds=feeds)
    assert report["good"] == 2 and report["bad"].startswith("error") and report["dup"] == 2 and report["hackernews"] == 1
    assert len(items) == 3 and len({i["id"] for i in items}) == 3  # the RSS served twice is stored once


# ---------------- sampling ----------------

def _pool(n_per=50):
    out = []
    for c in wf.THREAT_CLASSES:
        out += [{"id": f"{c}-{i}", "text": f"{c} text {i} long enough", "source": "s", "kind": "security"} for i in range(n_per)]
    out += [{"id": f"g-{i}", "text": f"ordinary text {i} long enough", "source": "s", "kind": "general"} for i in range(400)]
    return out


def _hint(text):
    return text.split()[0] if text.split()[0] in wf.THREAT_CLASSES else "benign"


def test_select_covers_every_class_and_never_exceeds_the_total():
    chosen, info = wf.select(_pool(), _hint, total=300, per_class=30)
    assert len(chosen) == 300 and len({c["id"] for c in chosen}) == 300
    for c in wf.THREAT_CLASSES:
        assert sum(1 for it in chosen if it["id"].startswith(c)) == 30
    assert info["candidates_per_class"]["phishing_kit"] == 50 and info["pool"] == 750


def test_select_prefers_ordinary_text_to_fill_the_rest_and_is_deterministic():
    a, _ = wf.select(_pool(), _hint, total=300, per_class=30, seed=5)
    b, _ = wf.select(_pool(), _hint, total=300, per_class=30, seed=5)
    c, _ = wf.select(_pool(), _hint, total=300, per_class=30, seed=6)
    assert [x["id"] for x in a] == [x["id"] for x in b] != [x["id"] for x in c]
    assert sum(1 for x in a if x["kind"] == "general") == 300 - 30 * len(wf.THREAT_CLASSES)


def test_select_copes_with_a_class_that_is_rare_in_the_pool():
    pool = [it for it in _pool() if not it["id"].startswith("carding_fraud")] + [
        {"id": "carding_fraud-0", "text": "carding_fraud only one", "source": "s", "kind": "security"}]
    chosen, info = wf.select(pool, _hint, total=100, per_class=30)
    assert info["candidates_per_class"]["carding_fraud"] == 1 and len(chosen) == 100


def test_the_guess_never_reaches_the_items():
    chosen, _ = wf.select(_pool(), _hint, total=60, per_class=5)
    assert all(set(it) <= {"id", "text", "source", "kind"} for it in chosen)


# ---------------- sheets ----------------

NAMES = ["a", "b", "c", "d", "e"]


def _items(n=100):
    return [{"id": f"i{k}", "text": f"text {k}", "source": "s", "kind": "general"} for k in range(n)]


def test_assign_gives_everyone_the_shared_items_and_splits_the_rest_exactly_once():
    out = wf.assign(_items(100), NAMES, shared=20)
    shared_sets = [set(x["id"] for x in rows) for rows in out.values()]
    common = set.intersection(*shared_sets)
    assert len(common) == 20
    uniques = [s - common for s in shared_sets]
    assert all(len(u) == 16 for u in uniques)  # (100 - 20) / 5
    assert len(set().union(*uniques)) == 80 and sum(len(u) for u in uniques) == 80  # nothing twice, nothing lost


def test_assign_orders_differ_between_people_and_is_deterministic():
    out = wf.assign(_items(100), NAMES, shared=40, seed=1)
    orders = [[x["id"] for x in rows] for rows in out.values()]
    assert len({tuple(o) for o in orders}) == 5
    assert [x["id"] for x in wf.assign(_items(100), NAMES, shared=40, seed=1)["a"]] == orders[0]


def test_one_labeller_has_nothing_to_share_and_no_labellers_is_an_error():
    assert len(wf.assign(_items(30), ["solo"], shared=10)["solo"]) == 30
    with pytest.raises(ValueError):
        wf.assign(_items(5), [])
    assert len(wf.assign(_items(5), NAMES, shared=99)["a"]) == 5  # shared is capped at what exists


def test_sheet_roundtrip_with_awkward_text(tmp_path):
    items = [{"id": "x1", "text": 'He said "hi", then\nleft — café 中文'}]
    p = tmp_path / "s" / "me.csv"
    wf.write_sheet(p, items)
    assert p.read_bytes().startswith(b"\xef\xbb\xbf")  # BOM so Excel shows accents correctly
    rows = list(csv.DictReader(open(p, newline="", encoding="utf-8-sig")))
    assert rows[0]["text"] == items[0]["text"] and rows[0]["label"] == ""


def _filled(tmp_path, rows, name="me.csv"):
    p = tmp_path / name
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["id", "text", "label", "notes"])
        w.writerows(rows)
    return p


def test_read_sheet_normalises_labels_skips_blanks_and_explains_mistakes(tmp_path):
    p = _filled(tmp_path, [["1", "t1", "Ransomware Leak", ""], ["2", "t2", "", ""], ["3", "t3", "benign ", ""],
                           ["4", "t4", "ransomwar_leak", ""], ["5", "t5", "nonsense", ""], ["6", "t6", "SKIP", ""]])
    rows, problems = wf.read_sheet(p)
    assert rows == {"1": ("ransomware_leak", "t1"), "3": ("benign", "t3"), "6": ("skip", "t6")}
    assert any("line 5" in x and "did you mean 'ransomware_leak'" in x for x in problems)
    assert any("line 6" in x and "nonsense" in x for x in problems)
    assert wf.progress(p) == (5, 6)  # five rows have something written in the label column, one is still blank


def test_a_sheet_missing_a_column_is_reported(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("id,text\n1,x\n", encoding="utf-8")
    rows, problems = wf.read_sheet(p)
    assert rows == {} and "missing column" in problems[0] and "label" in problems[0]


# ---------------- agreement statistics ----------------

def test_cohen_kappa_known_values():
    assert wf.cohen_kappa(["a", "b", "a", "b"], ["a", "b", "a", "b"]) == pytest.approx(1.0)
    assert wf.cohen_kappa(["a", "a", "b", "b"], ["b", "b", "a", "a"]) == pytest.approx(-1.0)
    assert math.isnan(wf.cohen_kappa(["a"], ["a"])) and math.isnan(wf.cohen_kappa(["a", "a"], ["a", "a"]))


def test_fleiss_kappa_matches_a_hand_computed_example():
    # 3 items, 2 raters: (a,a) (a,b) (b,b). P_bar = 2/3, P_e = 1/2, kappa = (2/3 - 1/2) / (1 - 1/2) = 1/3
    assert wf.fleiss_kappa([["a", "a"], ["a", "b"], ["b", "b"]]) == pytest.approx(1 / 3)
    assert wf.fleiss_kappa([["a", "a", "a"], ["b", "b", "b"]]) == pytest.approx(1.0)
    assert wf.fleiss_kappa([["a", "b"], ["a", "b"], ["b", "a"]]) < 0
    assert math.isnan(wf.fleiss_kappa([]))


@pytest.mark.parametrize("k,word", [(0.9, "almost perfect"), (0.7, "substantial"), (0.5, "moderate"), (0.3, "fair"),
                                    (0.1, "slight"), (-0.2, "worse than chance"), (None, "not enough"), (float("nan"), "not enough")])
def test_kappa_wording(k, word):
    assert word in wf.interpret_kappa(k)


def _people():
    mk = lambda pairs: {i: (lab, f"text {i}") for i, lab in pairs}  # noqa: E731
    return {
        "ann": mk([("1", "benign"), ("2", "exploit_sale"), ("3", "benign"), ("4", "skip"), ("only-ann", "benign")]),
        "bob": mk([("1", "benign"), ("2", "exploit_sale"), ("3", "credential_dump"), ("4", "benign")]),
        "cat": mk([("1", "benign"), ("2", "malware_sale"), ("3", "credential_dump"), ("4", "benign")]),
    }


def test_agreement_counts_shared_items_pairs_and_disagreements_and_ignores_skips():
    ag = wf.agreement(_people())
    assert ag["shared_items"] == 4 and ag["people"] == ["ann", "bob", "cat"]
    assert ag["pairs"]["ann~bob"]["n"] == 3 and ag["pairs"]["ann~bob"]["agree"] == round(2 / 3, 3)  # item 4 skipped by ann
    assert ag["pairs"]["bob~cat"]["agree"] == 0.75
    assert {d["id"] for d in ag["disagreements"]} == {"2", "3"}
    assert "fleiss_kappa" in ag and ag["items_labelled_by_everyone"] == 3  # items 1, 2, 3 (4 has a skip)
    assert ag["per_class_disagreements"]["credential_dump"] == 1


def test_agreement_with_nothing_shared_is_empty_not_an_error():
    ag = wf.agreement({"ann": {"1": ("benign", "t")}, "bob": {"2": ("benign", "t")}})
    assert ag["shared_items"] == 0 and ag["pairs"] == {}


# ---------------- consensus and split ----------------

def test_consensus_majority_ties_adjudication_and_skips():
    rows = {r["id"]: r for r in wf.consensus(_people(), adjudicated={"2": "exploit_sale"})}
    assert rows["1"]["label"] == "benign" and rows["3"]["label"] == "credential_dump"  # 2 of 3
    assert rows["2"]["label"] == "exploit_sale"                                        # team decided
    assert rows["4"]["label"] == "benign" and rows["4"]["raters"] == 2                  # the skip is not a vote
    assert rows["only-ann"]["label"] == "benign"
    undecided = {r["id"]: r for r in wf.consensus({"a": {"x": ("benign", "t")}, "b": {"x": ("exploit_sale", "t")}})}
    assert undecided["x"]["label"] == wf.REVIEW
    assert wf.consensus({"a": {"x": ("skip", "t")}}) == []


def _labelled(counts):
    return [{"id": f"{c}-{i}", "text": f"{c} {i}", "label": c} for c, n in counts.items() for i in range(n)]


def test_split_is_stratified_disjoint_deterministic_and_keeps_singletons_in_dev():
    rows = _labelled({"benign": 100, "exploit_sale": 30, "carding_fraud": 10, "threat_chatter": 1})
    dev, test = wf.split_dev_test(rows, 0.4, seed=1)
    assert len(dev) + len(test) == 141 and not ({r["id"] for r in dev} & {r["id"] for r in test})
    count = lambda part, c: sum(r["label"] == c for r in part)  # noqa: E731
    assert (count(test, "benign"), count(test, "exploit_sale"), count(test, "carding_fraud")) == (40, 12, 4)
    assert count(dev, "threat_chatter") == 1 and count(test, "threat_chatter") == 0
    assert (dev, test) == wf.split_dev_test(rows, 0.4, seed=1) and test != wf.split_dev_test(rows, 0.4, seed=2)[1]


# ---------------- the CLI flow end to end ----------------

THREATS = ["Selling 0day RCE for Exchange, price 2 XMR", "Fresh database dump with 3 million emails and passwords for sale",
           "Data will be published in 3 days unless the ransom is paid"]


def _fake_fetch():
    items = [{"id": sources.text_id(t), "text": t, "source": "fake", "kind": "security"} for t in THREATS]
    items += [{"id": sources.text_id(f"ordinary sentence number {i} about nothing"), "text": f"ordinary sentence number {i} about nothing",
               "source": "fake", "kind": "general"} for i in range(60)]
    return items, {"fake": len(items)}


def test_the_whole_workflow(tmp_path, capsys):
    base = str(tmp_path / "lab")
    assert cli.run(["pool", "--dir", base], fetch=_fake_fetch) == 0
    assert cli.run(["pool", "--dir", base], fetch=_fake_fetch) == 0  # a second run adds nothing new
    assert "63 -> 63" in capsys.readouterr().out
    assert cli.run(["sheets", "ann,bob", "--dir", base, "--total", "40", "--per-class", "2", "--shared", "10"]) == 0
    sheets = {p.stem: p for p in (tmp_path / "lab" / "sheets").glob("*.csv")}
    assert set(sheets) == {"ann", "bob"}
    for name, p in sheets.items():  # fill both sheets in with the same labels except for one item
        rows = list(csv.DictReader(open(p, newline="", encoding="utf-8-sig")))
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["id", "text", "label", "notes"])
            for k, r in enumerate(rows):
                lab = "exploit_sale" if "0day" in r["text"] else "benign"
                if name == "bob" and k == 0:
                    lab = "malware_sale"
                w.writerow([r["id"], r["text"], lab, ""])
    capsys.readouterr()
    assert cli.run(["check", "--dir", base]) == 0
    out = capsys.readouterr().out
    assert "progress" in out and "Fleiss kappa" in out and "items labelled by 2 or more people: 10" in out
    # Disagreements exist only if the changed item was a shared one; split must refuse an unresolved tie
    first_ann = list(csv.DictReader(open(sheets["ann"], newline="", encoding="utf-8-sig")))[0]["id"]
    first_bob = list(csv.DictReader(open(sheets["bob"], newline="", encoding="utf-8-sig")))[0]["id"]
    shared_item_disagrees = (tmp_path / "lab" / "final" / "disagreements.csv").exists()
    code = cli.run(["split", "--dir", base])
    if shared_item_disagrees:
        assert code == 1 and "no majority" in capsys.readouterr().out
        dis = tmp_path / "lab" / "final" / "disagreements.csv"
        rows = list(csv.DictReader(open(dis, newline="", encoding="utf-8")))
        with open(dis, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "text", "labels", "decided_label"])
            for r in rows:
                w.writerow([r["id"], r["text"], r["labels"], "benign"])
        code = cli.run(["split", "--dir", base, "--adjudicated", str(dis)])
    assert code == 0
    final = tmp_path / "lab" / "final"
    dev = list(csv.DictReader(open(final / "dev.csv", encoding="utf-8")))
    test = list(csv.DictReader(open(final / "test.csv", encoding="utf-8")))
    assert dev and test and not ({r["id"] for r in dev} & {r["id"] for r in test})
    assert "untouchable" in capsys.readouterr().out
    assert first_ann and first_bob


def test_pool_add_imports_your_own_public_examples(tmp_path):
    f = tmp_path / "mine.csv"
    f.write_text("text,source\nA public report describes a phishing kit sold on a forum,report\ntoo short,x\n", encoding="utf-8")
    base = tmp_path / "lab"
    assert cli.run(["pool", "--add", str(f), "--dir", str(base)]) == 0
    rows = list(csv.DictReader(open(base / "candidates.csv", encoding="utf-8")))
    assert len(rows) == 1 and rows[0]["source"] == "report"


@pytest.mark.parametrize("argv", [[], ["nonsense"], ["sheets"], ["sheets", "a,b"], ["check"]])
def test_cli_gives_help_instead_of_crashing(argv, tmp_path, capsys):
    assert cli.run(argv + ["--dir", str(tmp_path / "empty")]) == 1
    assert capsys.readouterr().out


def test_split_refuses_sheets_with_mistakes(tmp_path, capsys):
    sheets = tmp_path / "lab" / "sheets"
    sheets.mkdir(parents=True)
    _filled(sheets, [["1", "t", "wrong label", ""]], "x.csv")
    assert cli.run(["split", "--dir", str(tmp_path / "lab")]) == 1 and "Fix these first" in capsys.readouterr().out


# ---------------- scoring the whole pipeline on labelled data ----------------

def test_score_pipeline_measures_alerts_false_alarms_and_misses():
    texts = ["Selling 0day RCE for Exchange, price 2 XMR", "Fresh database dump with 3 million emails and passwords for sale",
             "Team lunch is on Friday, please reply with your food choice", "lunch menu"]
    labels = ["exploit_sale", "credential_dump", "benign", "benign"]
    r = realeval.score_pipeline(get_classifier(), texts, labels, pipeline.analyse)
    assert r["n"] == 4 and r["class_counts"]["benign"] == 2
    assert r["threats_missed_rate"] == 0.0 and r["false_alarm_rate"] == 0.0 and r["false_alarm_medium_or_higher_rate"] == 0.0
    assert r["macro_f1"] == 1.0 and r["accuracy"] == 1.0 and "rough guide" in r["warning"]
    assert sum(r["severity_of_detected_threats"].values()) == 2


def test_classes_with_fewer_than_ten_examples_are_reported_as_not_measured():
    texts = ["Team lunch is on Friday, please reply"] * 12 + ["Selling 0day RCE for Exchange, price 2 XMR"] * 3
    r = realeval.score_pipeline(get_classifier(), texts, ["benign"] * 12 + ["exploit_sale"] * 3, pipeline.analyse)
    assert r["classes_scored"] == ["benign"] and r["classes_too_few_to_score"] == ["exploit_sale"]
    assert r["macro_f1_scored_classes"] == 1.0
    enough = realeval.score_pipeline(get_classifier(), texts[:12] + [texts[-1]] * 10, ["benign"] * 12 + ["exploit_sale"] * 10, pipeline.analyse)
    assert enough["classes_too_few_to_score"] == [] and set(enough["classes_scored"]) == {"benign", "exploit_sale"}


def test_score_pipeline_counts_a_false_alarm_and_a_missed_threat():
    texts = ["Selling 0day RCE for Exchange, price 2 XMR", "Quarterly picnic photos", "Ransomware group will publish the stolen data"]
    # deliberately wrong labels: the first is called benign (so its alert is a false alarm), the second a threat (so it is missed)
    r = realeval.score_pipeline(get_classifier(), texts, ["benign", "exploit_sale", "ransomware_leak"], pipeline.analyse)
    assert r["false_alarm_rate"] == 1.0 and r["threats_missed_rate"] == 0.5
    assert ("benign", "exploit_sale", 1) in r["top_confusions"]
