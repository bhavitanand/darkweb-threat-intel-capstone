# Building a real labelled set

DarkLens's accuracy so far was measured on text our own team generated. This is the plan to measure it on real text, by hand-labelling a few hundred real, public examples. It is also the most useful thing a teammate can do for the project.

## How it works

```
python -m darklens label pool                       # gather public text (run on several days: the pool grows)
python -m darklens label sheets bhavit,krish,naisha,prateek,sahil
        # each person gets a private sheet; 40 items are labelled by everyone
python -m darklens label check                      # progress, mistakes, and how much people agree
python -m darklens label split                      # merge, then split into tuning (60%) and a locked test set (40%)
python -m darklens eval --csv labelling/final/test.csv --pipeline
```

Everything it writes goes in `labelling/`, which is **git-ignored**: it contains other people's text (news headlines and summaries) that must not be re-published. The sheets never contain the model's guess, so nobody is nudged.

## For each labeller (about 45 to 60 minutes)

1. Open your sheet in Excel or Google Sheets. Do not look at anyone else's sheet, and do not discuss items until `label check` has run.
2. For each row, read the `text` and write one value in the `label` column. Leave `notes` for anything you want to say.
3. Save as **CSV (UTF-8)** and send your file back privately.

### The labels

Label **what kind of threat the text is about**, even when it is a news report. If it does not describe a specific incident or offer of one of these kinds, it is `benign`.

| Label | Use it when the text is about... | Example (made up) |
| --- | --- | --- |
| `ransomware_leak` | An organisation hit by ransomware, a leak-site posting, an extortion countdown | "A ransomware group posted 340 GB stolen from a logistics firm and set a payment deadline" |
| `credential_dump` | Stolen logins, a leaked user database, combo lists, stealer logs offered, shared or reported | "A forum user is selling 2 million emails and passwords from a retailer breach" |
| `exploit_sale` | Someone selling an exploit, a zero-day, or access into a network | "Selling a working RCE for a popular VPN, 2 XMR" |
| `phishing_kit` | Fake login pages, phishing toolkits or phishing-as-a-service on offer | "A new kit clones bank login pages and relays one-time codes" |
| `malware_sale` | Malware (stealers, RATs, loaders, botnets, crypters) offered or rented | "A new infostealer is rented for $200 a month on a hacking forum" |
| `carding_fraud` | Stolen payment cards, carding shops, cash-out and fraud services | "A shop sells fresh card dumps with CVV" |
| `threat_chatter` | Planning or boasting about attacks (DDoS, defacement, hacktivism) without a sale or stolen data | "A group announces a DDoS campaign against ministries this week" |
| `benign` | Everything else: ordinary news, advice, product launches, opinion, a patch advisory | "How to set up two-factor authentication" |
| `skip` | You cannot judge it (cut off, not text, not in a language you read) | |

Rules of thumb:
- If two labels fit, choose the **main point** of the text. Hard cases are useful: they are exactly what the agreement check measures.
- A report of an attack on a named company that involved ransomware is `ransomware_leak`; advice on avoiding ransomware is `benign`.
- Do not search for the item or its source. Judge the text you were given.
- A vulnerability or patch advisory with no sale or incident is `benign`. A report of an exploited vulnerability or a malware analysis fits no class: use `skip` (see below).
- Personal, customer or employee data stolen, leaked or put up for sale (a breach report) is `credential_dump`. A ransomware or extortion group claiming a victim, or a report on a ransomware incident or leak-site activity, is `ransomware_leak`.

### What `skip` is for

Public security news is full of reports of attacks that fit none of the eight classes: an exploited vulnerability, an espionage group, a malware analysis, a takedown, a company confirming "a cyber incident" with no detail. Label these **`skip`** (out of scope). They are left out of scoring, so DarkLens is neither rewarded nor punished for how it treats them. Use `benign` only for text that is not about a threat at all, or is advice, a product, an opinion or a patch notice.

Examples of `skip`: "Attackers exploit a flaw in a chat server", "Researchers analyse a new infostealer", "Police take down servers behind a malware loader". Examples of `benign`: "Microsoft fixes 1,100 vulnerabilities this month", "How to spot a tax scam", a football result.

## What to do when labellers disagree

Across four labellers, 29 of the first 300 items were contested (14 of 177 on the 17 November set). Almost all were the benign-versus-skip line. The rules, applied in this order:

1. **Only unanimous items are scored** (`agreed.csv`). Contested items are listed in `contested.csv` and left out; nothing is decided by majority for the headline numbers. A majority-vote score (ties left out) is reported only as a sensitivity check.
2. **A contested item that turns out to be a real threat is never quietly dropped.** It is reported as a count ("6 contested threat items") so the detection rate is not flattered by removing hard cases.
3. **Guidance to reduce future splits** (not a retroactive relabel): a security *roundup, podcast, vendor product launch or funding story* is `benign`; a *trend or statistics report about attacks* and a *named incident with no stated data theft* are `skip`; an *article that only explains how attacks work, with no victim* is `skip` unless it is advice for the public, which is `benign`.
4. The policy is fixed before a new set is labelled, never edited to make a score look better.

## Machine-assisted labels, and checking them

With five busy people, the first set of labels for the 300 collected items was produced by four AI labellers (two passes from one assistant, one ChatGPT pass and one Gemini pass) working independently of each other and of DarkLens's own model, using the policy above. These are **silver labels**: useful for finding problems quickly, but not ground truth. The extra labellers are added with:

```
python -m darklens label pack --size 25              # copy-paste batches for another model, in labelling/pack/
python -m darklens label import NAME answers.txt     # read its numbered answers (messy formats tolerated, gaps reported)
python -m darklens label agree                       # pairwise agreement, Fleiss kappa, agreed and contested items
```

To learn how far they can be trusted, one human labels a short sample blind and the tool compares:

```
python -m darklens label validate make YOURNAME      # writes a 50-item sheet (all the real threats, plus a mix of the rest)
python -m darklens label validate check YOURNAME     # agreement and kappa against the machine, plus the disagreements
```

The 50 items take about 15 minutes. A kappa above about 0.6 means the silver labels are good enough to tune on; below that, human labels are needed.

## Keeping a test set untouched

Whenever the rules or thresholds are tuned against a set of items, that set is spent: it can no longer give an honest score. Each candidate records the date it was first fetched, so a later, untouched set can be carved out:

```
python -m darklens label pool                        # run again on a later day
python -m darklens label sheets NAMES --since 2026-11-17   # only items first seen on or after that date
```

The 300 items fetched on 16 November 2026 are the **tuning set**. Items fetched after that date are the test set.

## What comes out

- **Agreement.** Overlapping items show how often people agree (Cohen's and Fleiss' kappa). If we cannot agree with each other, the class is ambiguous and no model can score well on it. The disagreements are listed so the team can decide them together.
- **A locked test set.** Tune rules and retrain on the tuning half only. The 40% test half is used once, to report the final number.
- **A whole-product score** (`--pipeline`): macro-F1, how many real threats get no alert, how often ordinary text raises a false alarm, and how serious detected threats are rated.

## An honest limit: where the text comes from

Public security news is mostly reporting about attacks, not the underground sales posts themselves. So the pool finds plenty of ransomware and ordinary text, but very little for some classes (on the first run: phishing kits, malware sales and card fraud each had at most a handful). Two consequences:

- Any class with **fewer than 10 labelled examples is reported as "not measured"**, and no score is quoted for it.
- To fill gaps, add real **public** examples by hand: for example vendor threat-research write-ups or published research that quotes underground adverts. Put them in a CSV with a `text` column (and optionally `source`) and run `python -m darklens label pool --add yourfile.csv`. Only public text, and never anything obtained by logging in to a forum or market.

Even a fully labelled set of news text measures "real text about these threats", not underground-forum text. The documentation says so wherever a number is quoted. The one thing that would close that gap is a legitimately obtained forum dataset approved by your supervisor.
