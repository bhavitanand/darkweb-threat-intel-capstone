# Real labelled examples

This folder is for **real** text, labelled by a person, used to measure the classifier honestly (see [docs/accuracy.md](../../docs/accuracy.md)). It ships with only a template.

Run an evaluation with:

```bash
python -m darklens eval --csv data/real_labelled/my_labels.csv
```

## Format

A CSV with a header and two columns:

| text | label |
| --- | --- |
| `Short description or snippet of the post` | one of `ransomware_leak`, `credential_dump`, `exploit_sale`, `phishing_kit`, `malware_sale`, `carding_fraud`, `threat_chatter`, `benign` |

## Rules for what goes in

- **Public text only**, such as a claim on a public tracker or a public advisory. Never log in to anything to get it.
- **No real credentials, personal data or leaked files.** If a snippet contains email:password lines, mask the password or leave the example out.
- Keep each text to a short snippet (a few sentences).
- Label what the post **is**, not how worrying it is. Use `benign` for ordinary text, and include plenty of it, because that is where false alarms come from.
- Aim for at least 50 examples (below that the score is mostly noise), ideally a few hundred with every class represented.
- Do not commit files you are not allowed to share. Add them to `.gitignore` if unsure.

`template.csv` shows the shape.

## Real datasets shipped in this folder (used for training and for the honest test)

| File | What | Licence and attribution |
| --- | --- | --- |
| `hibp_breaches.csv` | 1,033 real, verified data breaches with their prose write-ups, each labelled `credential_dump`. Spam lists and fabricated entries are excluded. | Breach data from **[Have I Been Pwned](https://haveibeenpwned.com)** by Troy Hunt, licensed [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/). Descriptions are cleaned of HTML. |
| `nvd_advisories.csv` | 1,043 real vulnerability descriptions, each labelled `benign`: security vocabulary, but an advisory and not a threat post (see [labelling.md](../../docs/labelling.md)). Withdrawn (`** REJECT **`) entries are excluded. | **[NIST National Vulnerability Database](https://nvd.nist.gov)**, US government data in the public domain. |

Columns: `id, source, added, label, text`. `added` is the date the entry was added to its source, which is what lets the newest period be held out as a test.

Rebuild them with `python -m darklens data build` (needs the internet, no key). Measure with `python -m darklens eval --real`.
