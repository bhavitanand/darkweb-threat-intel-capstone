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

## 3. Known weaknesses

- **Ordinary text can get a ransomware label.** The text model sometimes labels harmless text "ransomware leak" with about 30% confidence. The score stays Low and no alert is raised, but the label on a Low alert can be misleading. Cause: the model was trained only on synthetic data.
- **Keyword rules miss unusual wording.** For example a database sale that avoids the words "database", "dump", "emails" and "passwords". Database-for-sale posts are covered by rule `DL-CRD-005`, with tests for look-alikes that must stay Low.
- **Threat chatter is the weakest class** in the synthetic evaluation.
- **No measurement on forum and market posts.** There is no real labelled set for them.

## 4. How to measure properly (and how you can help)

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
