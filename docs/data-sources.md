# Data sources, what is stored, and what is not

## Sources

| Source | What it provides | Key needed | Terms that shape this project |
| --- | --- | --- | --- |
| [Ransomware.live](https://www.ransomware.live) | Public claims that a named organisation was hit by a ransomware group, with the group, country, sector and website | **Yes, free.** Get one at <https://my.ransomware.live>, set `RANSOMWARE_LIVE_API_KEY` | [Terms & Conditions](https://www.ransomware.live/t&c): non-commercial use with a linked attribution, 30-minute cache, **no re-serving or publishing of the raw data** (see below) |
| [ThreatFox](https://threatfox.abuse.ch) (abuse.ch) | Malicious indicators (IPs, domains, hashes) with a confidence value | Free `ABUSECH_AUTH_KEY` from <https://auth.abuse.ch/> | Free under abuse.ch fair-use principles for non-commercial use. Commercial use may need their paid API. IOCs older than six months are expired |
| Forum posts | Short text snippets | No | Live collection needs the allowlisted Tor crawler, which ships disabled (see [SECURITY.md](../SECURITY.md)) |
| Demo samples | Made-up posts and claims in `data/samples/` | No | Fictional. Labelled with a Demo badge |

Live collection is off until `AUTO_INGEST_MINUTES` is set on the server (or `python -m darklens ingest --live` is run). A source without its key is **skipped**, and the website's "Where this data comes from" card says so. Without any key the site shows only the demo samples.

## Ransomware.live: what its terms mean for this code

The terms (section 4 and 6, last updated August 2026) are why the project behaves as follows:

| Term | What DarkLens does |
| --- | --- |
| Use the free PRO API with a personal token. The legacy API is "personal use only". | Live mode uses `api-pro.ransomware.live` with `X-API-KEY`, and is skipped without a key. |
| Non-commercial use only; commercial use needs written approval. | This is an academic capstone with no revenue. If it ever becomes commercial, ask the owner first. |
| Data is cached 30 minutes; do not poll more often. | `AUTO_INGEST_MINUTES` has a floor of 30, and responses are cached on disk for 30 minutes. |
| Do not stand up an API or feed that re-serves the data, and do not publish the raw data in any form. | Items from this source are flagged `no_redistribute`. The API **never returns their free text**, and they are **left out of the CSV, STIX and feedback exports**. The website shows the organisation name, group and date with a link back, our own score and reasons, and clues, which is a dashboard displaying the data with attribution rather than a feed of it. |
| Name Ransomware.live as the source, with a link, on every page that shows the data. | A "Source: Ransomware.live" credit with a link appears on the overview, alert list, report, connections page and the footer. |
| Do not relay your users' queries to them; do not use several keys to dodge limits. | Visitors query DarkLens, never Ransomware.live. One key is used. |
| A listing is not a confirmed breach. | The site says so wherever it credits the source. |

This is our reading of the terms, not legal advice. The owner can grant exceptions in writing (<https://ransomware.live/contact>); asking for approval to show more is the right route if a feature needs it.

## What is stored

- The title and a short snippet of each item. For Ransomware.live, the organisation name, group, sector and website. (The snippet is kept so the item can be scored, but is never returned by the API.)
- Alert scores and the reasons behind them.
- Clues extracted from the text (wallets, domains and so on).
- Your watchlist entries (domains and emails you add). **The watchlist is shared by every visitor**, so do not put confidential information in it.
- Reviewer feedback: the alert, the verdict, and an anonymous salted hash of the visitor.
- A little state: the last collection status and which notifications were already sent.

## What is never stored

- **Plaintext passwords.** `email:password` pairs are masked before anything is written.
- Full pages, leaked files or databases. Only short snippets.
- Visitor IP addresses or accounts. There are no accounts. Feedback uses a salted hash only to allow one vote per visitor.

## A note on real organisation names

Ransomware.live claims name real organisations. The names are already public on the source; DarkLens repeats them with attribution to help people check whether they are affected. A claim is an accusation by criminals, not a confirmed breach. If you are a named organisation and want an entry removed from DarkLens, open a "takedown" issue; the source's own removal process is in section 9 of its terms.

## Retention

Real items older than `RETENTION_DAYS` (default 90, `0` keeps everything) are deleted after each live collection. Demo items, and any item a reviewer has given feedback on (because it is labelled data), are kept.
