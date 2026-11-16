# Accuracy: what has been measured, and what has not

Short version: the classifier works on the synthetic test set, behaves sensibly on real ransomware claims after one fix found by testing on real data, and has **not** yet been measured on real forum or market posts, because no labelled set of those exists yet. This page is meant to be read critically.

## 1. Synthetic held-out templates (the headline number)

Macro-F1 on 350 samples built from sentence structures the model never saw in training (`python -m darklens eval`):

| Predictor | Macro-F1 |
| --- | --- |
| Hand-written rules only | 0.771 |
| TF-IDF + logistic regression only | 0.547 |
| **Hybrid (default)** | **0.836** |

This shows the method works. It does **not** show how well it works on real text, because the corpus is generated from templates written by the same team.

## 2. Real Ransomware.live claims (measured 16 November 2026, n = 100)

`python -m darklens eval --live-claims` fetches the 100 most recent public claims (it needs `RANSOMWARE_LIVE_API_KEY`) and checks what DarkLens does with them. Every one of them is a genuine ransomware claim, so this measures one class only. The figures below were taken locally, for research, from the legacy API, whose entries carry a text description.

**Re-measured on the PRO API (16 November 2026, n = 100, the data the deployed site really uses):** all 100 recognised as ransomware claims, and they score 64 Medium, 32 High and 4 Critical, none Low (scores 57 to 95). The PRO responses do carry descriptive text, so the rules fire as they did on the older API. Worth knowing: a few Critical scores come from several rules stacking on one description (for example "database dump" wording on a ransomware claim), so Critical on a claim about an unrelated organisation deserves reviewer scrutiny.

| | Before | After |
| --- | --- | --- |
| Recognised as "ransomware leak" | 88 / 100 | 100 / 100 |
| Scored Medium or higher | 10 / 100 | 100 / 100 (68 Medium, 32 High, 0 Low) |

What went wrong first: real claim descriptions are short and templated ("...a verified set of records... scheduled for publication... Deadline: 2026-11-19"), so few keyword rules fired and 90% of real claims scored Low. The synthetic test set could never have shown this. The fix was to treat "this came from a ransomware leak-site tracker" as evidence (the source says so), and to add the real wording to the countdown rule. Regression tests in `tests/test_real_data.py` keep it fixed.

Be careful reading the "100 / 100": recognising the category is partly true by construction now (the source decides it). The meaningful result is the score distribution, and whether reviewers agree with it.

## 3. The "not sure" outcome

The text model labelled almost every ordinary sentence as a threat type, but with low confidence. On 23 everyday sentences (a picnic, a meeting reminder, a recipe) it guessed a threat type at 19 to 39% confidence in 18 cases. So when the model is the **only** evidence and its confidence is below **40%**, DarkLens now says **"Not sure"** and raises no alert. The 40% cut was chosen from data: on the 350 synthetic test samples it removes 26 wrong labels for 17 right ones among classifier-only guesses.

What it does not touch: anything backed by a detection rule, a watchlist mention, leaked credentials, or a source that states the category (a leak-site tracker). A post that mentions your watched domain but looks like nothing in particular still alerts, labelled "Not sure" rather than a threat type.

Still imperfect: the cut is on confidence, and the model is sometimes confidently wrong. One everyday sentence ("The server maintenance window is Sunday 2am to 4am") still gets a ransomware label at 59%. The real fix is retraining on real labelled data (see below).

## 4. Known weaknesses

- **Confidently wrong labels remain possible.** Ordinary text at 40% confidence or higher can still receive a threat label, usually with a Low score. Cause: the model was trained only on synthetic data.
- **Keyword rules miss unusual wording.** For example a database sale that avoids the words "database", "dump", "emails" and "passwords". Database-for-sale posts are covered by rule `DL-CRD-005`, with tests for look-alikes that must stay Low.
- **Threat chatter is the weakest class** in the synthetic evaluation.
- **No measurement on forum and market posts.** There is no real labelled set for them.

## 5. How to measure properly (and how you can help)

### Reviewer feedback in the website

Every alert report has an **"Is this right?"** box. Votes are stored, can be exported with `GET /api/export/feedback.csv`, and scored with:

```bash
python -m darklens eval --feedback
```

### Your own labelled data

Create a CSV with two columns, `text` and `label`, where `label` is one of `ransomware_leak`, `credential_dump`, `exploit_sale`, `phishing_kit`, `malware_sale`, `carding_fraud`, `threat_chatter`, `benign`:

```bash
python -m darklens eval --csv data/real_labelled/my_labels.csv
```

It prints macro-F1 for rules, model and hybrid, plus a per-class report, and warns when there are fewer than 50 examples (below that the number is mostly noise). See `data/real_labelled/README.md` for how to build a set safely: only public text, no real credentials, no personal data.

### Target

A few hundred hand-labelled real posts across the eight classes would let the model be retrained on real text and its figure reported honestly. Until then, treat the 0.836 as an upper bound on real-world performance.
