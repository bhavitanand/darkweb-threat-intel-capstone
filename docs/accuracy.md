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

The text model labelled almost every ordinary sentence as a threat type, but with low confidence. On 23 everyday sentences (a picnic, a meeting reminder, a recipe) it guessed a threat type at 19 to 39% confidence in 18 cases. So when the model is the **only** evidence and its confidence is below the cut, DarkLens says **"Not sure"** and raises no alert. The cut started at 40% and was **raised to 60%** after measuring 234 real ordinary news items (section 5). The cost on synthetic threat posts is small (about 4 points of recall at 60%) and the gain is large.

What it does not touch: anything backed by a detection rule, a watchlist mention, leaked credentials, or a source that states the category (a leak-site tracker). A post that mentions your watched domain but looks like nothing in particular still alerts, labelled "Not sure" rather than a threat type.

Still imperfect: the cut is on confidence, and the model is sometimes confidently wrong. One everyday sentence ("The server maintenance window is Sunday 2am to 4am") still gets a ransomware label at 59%. The real fix is retraining on real labelled data (see below).

## 4. Known weaknesses (summary)

- **Confidently wrong labels remain possible.** Ordinary text at 60% confidence or higher can still receive a threat label, usually with a Low score (the cut was raised from 40% after real-news measurement; see section 5). Cause: the model was trained only on synthetic data.
- **Keyword rules miss unusual wording.** For example a database sale that avoids the words "database", "dump", "emails" and "passwords". Database-for-sale posts are covered by rule `DL-CRD-005`, with tests for look-alikes that must stay Low.
- **Threat chatter is the weakest class** in the synthetic evaluation.
- **No measurement on forum and market posts.** There is no real labelled set for them.

## 5. Measured on real public text (16 November 2026)

**What was measured.** 300 real items collected from public security-news and general-news feeds (headlines and short summaries). Of these: **234 ordinary (benign)**, **54 attack or exploitation news that fits none of the eight classes** (set aside as "skip", not scored), and **12 real threats** (5 ransomware or extortion, 6 breach reports, 1 phishing kit). The whole product was scored (`eval --csv ... --pipeline`), not just the text model.

**How the labels were made.** Four AI labellers labelled all 300 items independently of the DarkLens model and of each other, following the written policy in [labelling.md](labelling.md): two passes from the first assistant (the second from a fresh agent with no sight of the first), one ChatGPT pass and one Gemini pass (Gemini Hydrogen, thinking level High; ChatGPT with its Think mode on for the later batches). These are **machine ("silver") labels, not human ones.** A 50-item validation sheet for a human is prepared (`label validate make`), and until a person has checked a sample, the figures below should be read as provisional. One mechanical numbering slip in the first pass (one item shifted) was found by comparison and corrected.

| Labeller pair | Agreement, all 300 | Agreement, items nobody skipped |
| --- | --- | --- |
| First assistant, pass 1 and pass 2 | 98% (kappa 0.933) | 100% (246 items) |
| ChatGPT and first assistant pass 1 | 92% (kappa 0.788) | 99% (228) |
| ChatGPT and first assistant pass 2 | 91% (kappa 0.776) | 99% (230) |

Gemini agrees with each of the other three on 95% of all 300 (kappa 0.87), and with ChatGPT on all 229 items neither skipped. All four together: Fleiss kappa **0.850**; all four agree on 271 items and 29 are contested. Almost every split is the benign-versus-skip boundary (ChatGPT skips more). Six contested items are about real threats (for example a breach by an exploited flaw, an incident-response trends report, an essay on ransom notes) and need a human tie-break. The figures in the tables below were measured on the earlier two-pass agreed set; re-scoring on the agreed set (the same 226 scorable items under three or four labellers) (226 scorable items: 215 benign, 5 ransomware, 6 credential dump) gave 0.9% false alarms at any level and none at Medium or higher, about 9% of real threats missed (1 of 11) and 4 of 11 detected with the wrong type, with only benign having enough examples to score. As a sensitivity check, scoring on majority-vote labels instead (289 items, 11 two-two ties left out; 227 benign, 5 ransomware, 7 credential dump) gave 1.8% false alarms at any level, 0.4% at Medium or higher, and 2 of 12 real threats missed. The false-alarm conclusion holds either way; the detection figure moves with a single item and should not be quoted as a rate.

### What the real news revealed, and what changed

| Measured on the 234 ordinary items | Before | After |
| --- | --- | --- |
| Raise **any** alert | 32.1% (75) | **2.6%** (6) |
| Raise **Medium or higher** | 3.0% (7) | **0.9%** (2) |
| Real threats (12): raise an alert | 11 | 11 |
| Real threats (12): alert with the **right type** | 6 | 7 |
| Synthetic hybrid macro-F1 | 0.836 | 0.890 |

What was found and fixed:
- **Three rules fired on everyday vocabulary.** "Zero-day" (patch-news), "initial access" (incident-response reports) and "dumps" (a story about rubbish dumps) scored as exploit sales or card fraud. They now require sale wording. A first fix demanded the word "selling" and lost a genuine access listing, caught by a regression test, so the rules also accept "listings", a price or a payment wallet.
- **The model labelled ordinary text as a threat** at 40 to 60% confidence. Raising the "Not sure" cut from 40% to 60% removed nearly all of it, but also silenced real breach and extortion news that the model had only been flagging by accident. Two narrow rules were added for what was missing (breach reports and extortion-group claims), which brought detection back to 11 of 12.
- **The rule boost in the hybrid was an untuned guess** (1.5). Measured at 1.5, 3, 5, 8 and 12, the best overall was 8.

### Read these numbers with care

- **The 300 items were used to find the problems**, so the 2.6% and 0.9% are optimistic. The honest test is items collected *later*; that was run on 17 November and is reported in the next subsection.
- **The labels are machine-made** (four models, high but not perfect agreement) and unvalidated by a human (see above). Models agreeing with each other shows consistency, not correctness.
- **Only 12 real threats.** Detection rates on 12 items move by 8 points per item. Treat "11 of 12" as a smoke test, not a rate.
- **Classes with fewer than 10 examples are reported as "not measured":** ransomware (5), credential dump (6) and phishing kit (1). **Exploit sale, malware sale, card fraud and threat chatter had no examples at all**, because public news is mostly *about* attacks rather than the underground posts themselves. Those four classes remain unmeasured on real text.
- **News text is not underground-forum text.** This measures how DarkLens behaves on real public writing, chiefly how often it raises false alarms, not how well it spots real underground posts.
- The synthetic 0.890 was chosen using the synthetic test set, so it is slightly flattered. The real-data measurement is the number to trust more.
- Breach reports still tend to be typed "ransomware leak" rather than "credential dump" (4 of 6).

### The untouched test (17 November 2026)

**What.** 177 items first collected on 17 November, after the rules and thresholds above were settled, kept in a separate folder and scored once before any change. Labelled by two independent AI labellers (the first assistant and ChatGPT with Think on; kappa 0.838 on all 177, 0.944 on the 123 neither skipped); **163 items agreed**, 14 contested. Gemini was not run on this set. Scorable agreed items: 113 benign, 7 credential dump, 1 ransomware, 1 phishing kit.

| Measured once, before any change | Result |
| --- | --- |
| Ordinary news given **any** alert | **0 of 113** (0%) |
| Real threats that got no alert | **3 of 9** (breach reports) |
| Real threats given the wrong type | 0 |

So the false-alarm result held on data DarkLens had not been tuned on, but detection did not: the rule for breach reports missed phrasings such as "data exposed in a breach", "150,000 impacted by third-party breach" and "payment card data exposure". The rule was extended (with regression tests and ordinary-text guards), which brings the miss rate to 1 of 9 and adds no false alarms on either set. **That second figure is not an honest test**, because the fix was written after seeing these items: the 17 November set is now spent, and the next untouched set must come from items collected later. With 9 threats, treat the first figure as a warning that real-world detection is lower than the tuning set suggested, not as a rate.

### Trained and measured on real data (17 November, second round)

The first round showed the text model had never seen real text: it was trained only on synthetic templates. This round fixes that with two free, redistributable real datasets (see [data/real_labelled](../data/real_labelled/README.md)): **1,033 real breach write-ups** from Have I Been Pwned (CC BY 4.0), every one a real `credential_dump`, and **1,043 real vulnerability advisories** from NVD (public domain), which are security vocabulary but, under the labelling policy, benign. The advisories are the important half: they are the hard negatives that stop a model from crying wolf at any text that mentions "exploit" or "vulnerability".

**Protocol.** The model is trained on the synthetic templates plus the real breaches added *before 2026* and 80% of the advisories, then tested on what it never saw: the **117 breaches added in 2026** and the **203 held-out advisories**. Reproduce it with `python -m darklens eval --real`; CI enforces it (`tests/test_real_accuracy_gates.py`).

| Measured on text the model never saw | Before (synthetic-only model) | After |
| --- | --- | --- |
| 2026 real breaches: raise an alert | 70.9% | **100%** |
| 2026 real breaches: **right type** (credential dump) | 35.9% | **100%** |
| Unseen real advisories wrongly raising an alert | 9.9% | **0%** |
| Untouched 17 Nov news set: real threats missed / wrong type | 1 of 9 / 0 | **0 of 9 / 0** |
| Same news set: ordinary items given any alert | 0 of 113 | 0 of 113 |
| Tuning news set: ordinary items given any alert (Medium or higher) | 0.9% (0) | 0.5% (0) |

How it got there, in order, each step measured on breaches added before 2026 (tuning), then 2025 (validation) before touching 2026: new bounded rules written from the wording of real breach reports (alert rate 78% to 93%); training the text model on the real breaches and advisories with balanced class weights; a down-weighting of the real examples (breaches 0.15, advisories 0.02, chosen by grid search) so eight classes stay in balance; re-tuning the rule boost (8 to 12); and letting a high-weight rule suppress "benign" more strongly (the model had learned from advisories that "exploit" means a patch notice, and exploit-sale recall had fallen to 0.38 until this was fixed).

**Read these numbers with care.**
- **The 100% figures are flattered.** Breach write-ups share one distinctive style, so a model trained on earlier ones recognises later ones easily. They show the model learned real breach language, not that it will be 100% on any breach news. The independent checks are the two news sets (different style, third-party text), where it also does well, but they are small (9 and 11 real threats).
- **The news sets were used to choose the weights and the boost.** The untouched 17 November set was "untouched" for the rules but was looked at while picking these settings, so the cleanest next test is a set collected after today.
- **The synthetic score is no longer an independent test.** The rules alone now score 1.0 on the synthetic held-out templates, because they were extended after those templates had been read. It stays as a regression check only. The text model on its own scores 0.30 on made-up forum templates: it is now shaped by real text, so on forum-style sale posts it relies on the rules. That is why sale and planning wording is covered by rules, and why those classes still need real examples.
- **Still unmeasured on real text:** exploit sales, malware sales, card fraud, threat chatter and phishing kits (public data has no such text), and ransomware claims (needs the Ransomware.live key). Breach severity is conservative: 82% of the unseen breaches reach Medium or higher, the rest are Low.

## 6. How to measure properly (and how you can help)

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
