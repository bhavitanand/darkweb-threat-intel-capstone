# Changelog

All notable changes, newest first. Dates are when the change was made. The project follows [Semantic Versioning](https://semver.org) while it is below 1.0: a minor number (0.x) adds features, a patch number (0.x.y) is fixes and measurements. Each version below is a git tag.

| Version | Date | In one line |
| --- | --- | --- |
| [0.3.0](#030---2026-11-23) | 2026-11-23 | Accounts and private workspaces, email digest, webhook and API keys, MISP and TAXII, GitHub advisories, indicator lookups, CodeQL, threat model |
| [0.2.1](#021---2026-11-17) | 2026-11-17 | Trained and tested on real data, keyless sources, edge-case hardening |
| [0.2.0](#020---2026-11-16) | 2026-11-16 | React website, live data, Postgres, feedback, exports, notifications, CI |
| [0.1.0](#010---2026-11-15) | 2026-11-15 | Core engine: rules, classifier, scoring, indicators, graph, API, evidence packs |

## [0.3.0] - 2026-11-23

### Added
- **Accounts and private workspaces.** Sign in with an emailed one-time link (no passwords). Each workspace has its own private watchlist (domains, emails, software), an "About what you watch" feed scored against only that list, an optional daily or weekly **email digest** (only sent when something is new), an **alert webhook** for Slack, Discord or Teams with a minimum level, and **API keys** (shown once, read-only, revocable). Deleting the account removes everything. New pages Workspace and Sign in; routes under `/api/auth/*`, `/api/me`, `/api/account`, `/api/workspace*` (see `docs/api.md`).
- **GitHub Advisory Database** as a new live source (no key; `GITHUB_TOKEN` optional), and **indicator lookups** (`GET /api/enrich`) against OTX, VirusTotal and GreyNoise for whichever free keys are set (`OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`), validated, cached and capped at 12 lookups a minute.
- **MISP export** (`/api/export/misp.json`) and a read-only **TAXII 2.1** server (`/taxii2/`), so other tools can pull the feed. Restricted sources stay excluded.
- Optional **Sentry** error reporting (`SENTRY_DSN`, off by default, no user text sent), a **CodeQL** workflow, and a written **threat model** (`docs/threat-model.md`).
- **Frontend:** new Sign in and Workspace pages (private entries, "About what you watch", digest and webhook settings, API keys shown once, delete account); the sign-in link is spent once even when React runs an effect twice.
- About 110 new backend tests (accounts, isolation between two users, webhook safety, exports) and 8 frontend tests.

## [0.2.1] - 2026-11-17

### Added
- **Watch your software.** The watchlist now takes product and vendor names ("Software or vendor"). A report of an exploit, breach or attack on something you run, or a CISA-listed exploited flaw in it, is High instead of Low; a passing mention is only a Low hint. Whole-word matching, so short names do not fire inside other words.
- **Alerts paging and filtering in the database:** `GET /api/alerts` takes `offset`, filters severity, category and text before limiting (previously it limited first, so a filter could hide matches), and returns the match count in `X-Total-Count`.
- The first **untouched real-data test** (177 items first collected on 17 November) is reported in `docs/accuracy.md`: no false alarms on 113 ordinary items, but 3 of 9 real breach reports missed.

- **Real-data test suite** (`tests_real/`): every component on the collected real items (robustness, determinism, speed, indicators, masking, the whole API, exports, hidden-text guarantee), accuracy floors on the labelled real sets, and a smoke test of the deployed site on its live feeds.
- Website: the Alerts page filters and pages on the server and shows the true total (it used to say "of 1000" when 4,762 existed); the Overview asks for five alerts instead of downloading a thousand; per-page browser titles; a shared link such as `/alerts` now opens the right page; security headers; fonts bundled instead of loaded from Google; four one-click examples on "Check a post" (two threats, two everyday stories).

### Added (a wider net, no keys needed)
- **Four new live sources that need no key**, so a live site has real data immediately: **Have I Been Pwned** recent real breaches (CC BY 4.0, credited), **17 security news feeds** (headline, short summary and a link; flagged `no_redistribute`, so never returned, searched or exported), **OpenPhish** live phishing pages, and the **Feodo Tracker** botnet list. CISA's exploited flaws are enriched with **EPSS**, the modelled chance of exploitation in the next 30 days. A first live run with no keys collected about 380 items and raised about 240 alerts in 28 seconds.
- A new item kind, `breach_report`: a public, verified breach list is itself evidence, so those are always credential dumps with a "Listed as a real data breach" signal.
- The site footer credits every source; the status card names each one.

### Added (accuracy on real data)
- **Real training and test data, free and redistributable:** `data/real_labelled/hibp_breaches.csv` (1,033 real breaches, Have I Been Pwned, CC BY 4.0) and `nvd_advisories.csv` (1,043 real vulnerability advisories, NIST NVD, public domain). `python -m darklens data build` refreshes them; `python -m darklens eval --real` runs the honest protocol (train before 2026, test on breaches and advisories never seen); `tests/test_real_accuracy_gates.py` enforces it in CI.
- **The text model is now trained on real text** (breaches as `credential_dump`, advisories as benign hard negatives, down-weighted so the eight classes stay balanced; balanced class weights). On unseen 2026 breaches: detected and correctly typed 36% to 100%; unseen advisories wrongly alerting 9.9% to 0%; untouched news set: 9 of 9 real threats right (was 8 of 9 detected).
- New rules written from the wording of real breach reports (`DL-CRD-007` hacked or breached with data taken, `DL-CRD-008` breach with a ransom demand), plus sale and planning wording that was missing: "sell a working exploit", "foothold" with a price or escrow, group attack intent, "call to arms". Business talk ("target a 10% increase", "hit our targets") is excluded. The rule boost is re-tuned (8 to 12) and a strong rule now suppresses "benign" harder.
- Fixes found on the way: the classifier file (now 8 MB) was reloaded from disk on every analysis, including every `/api/analyse` request; it is cached in memory. `save()` ignored a redirected model path. The NVD cleaner did not skip `** REJECT **` entries.
- Honest changes to what we claim: the synthetic held-out score is no longer an independent test (the rules alone score 1.0 on it after being extended), so it is a regression check; see `docs/accuracy.md`.

### Fixed (edge cases)
- **Slow input.** Crafted 20,000-character text took 6 to 13 seconds to analyse (quadratic regexes in the domain and email extractors, the combolist rule and the password masker), enough for one client to pin the server. All are bounded and anchored now; the worst of 38 hostile inputs takes 0.08 seconds. Only the first 5,000 characters of a very long text are classified (indicators and watchlist matches still search all of it), and the result and the page say so.
- A huge `offset` crashed `/api/alerts` with a 500; it is clamped.
- A malformed link such as `/#/alerts/%E0%A4%A` blanked the whole page (`decodeURIComponent` threw while rendering).
- Server validation errors showed as "[object Object]"; they are now sentences. Over-long pasted text is caught before sending, with a counter. Rate limiting and a sleeping server get plain-language messages, and the status badge re-checks every 30 seconds instead of staying "online" after an outage. A missing alert explains that old alerts expire.
- One malformed record (a number where text is expected, a list, an enormous string) in a live feed crashed that source's whole collection; every parser now coerces and bounds fields and skips only the bad record. A damaged feed cache file is refetched instead of failing, and cache writes are atomic.
- A notification the channel refuses (a 4xx) was retried forever and silenced every later alert; it is now skipped, while network and server errors are still retried. Titles are cleaned to one bounded line, so a newline can never reach an email header.
- CSV export also neutralises formulas hidden behind leading spaces or invisible characters.
- Watchlist validation: domains with a leading or trailing hyphen or a label over 63 characters are refused; names such as `c++` and `asp.net` are accepted.
- Search over alerts could have revealed whether hidden Ransomware.live text contained a word; hidden text is now excluded from search.
- Adding a watchlist entry re-scored every stored item (about 16 seconds at 4,800 alerts, under a global lock, open to anyone). It now re-scores only the items that mention the entry, and the shared list is capped at 100.
- "Check a post" ignored watched software.
- Live collection through the API was open to anyone when no token was configured; it now needs `INGEST_TOKEN`, compared in constant time.
- Overview tile "Alerts raised" counted 4,461 lone feed indicators as alerts; they are now shown separately. The "Stolen logins" description no longer claims a list is being sold for a breach news story.
- A routine "vendor fixes a bug" story no longer reads as an emergency for someone watching that vendor (High needs an attack or breach; a patch or flaw is Medium).
- Dockerfile runs as a non-root user and has a health check; dependency versions have upper bounds.

### Changed
- Rule `DL-CRD-006` also recognises breach news worded as data "exposed", "impacted by a breach", "breach notification" and exposed card numbers, with regression tests and ordinary-text guards. This was written after seeing the 17 November set, so that set is now spent and the post-fix figure is not an honest test.
- `docs/labelling.md` now states how disagreements between labellers are handled.

## [0.2.0] - 2026-11-16

### Added
- **React website** (`frontend/`): overview, alerts, full alert report, connection map, watchlist, "check a post", a "Get started" guide and "How it works". Deployed separately from the API.
- **Live data on a schedule** (`AUTO_INGEST_MINUTES`) with per-source status shown on the Overview, demo data clearly badged, and retention (`RETENTION_DAYS`).
- **Postgres support** (`DATABASE_URL`) alongside the SQLite default, with automatic reconnect.
- **Reviewer feedback** ("Is this right?"), feedback summary and labelled CSV export.
- **Accuracy tooling:** `python -m darklens eval --csv | --feedback | --live-claims`.
- **Exports:** CSV (spreadsheet-safe) and STIX 2.1.
- **Notifications** to a webhook (Slack, Discord, Teams) or email, de-duplicated and capped.
- **Rate limiting**, request size limits, optional `INGEST_TOKEN`, optional CORS allowlist (`ALLOWED_ORIGINS`), and a HEAD-friendly `/api/health`.
- **Rule `DL-CRD-005`** (database offered for sale) with edge-case tests.
- Documentation (`docs/`), CI workflow, Dependabot, issue and pull request templates.

### Changed (after measuring real public news; see docs/accuracy.md)
- On 234 real ordinary news items, alerts on ordinary text fell from 32% to 2.6% (Medium or higher: 3.0% to 0.9%), with real-threat detection held at 11 of 12 (provisional: machine-assisted labels, tuned on the same items).
- Rules `DL-EXP-001`, `DL-EXP-003` and `DL-FRD-001` now need sale wording (they fired on "zero-day" patch news, "initial access" incident reports and "rubbish dumps"); a weak `DL-EXP-004` keeps bare zero-day mentions. New rules `DL-CRD-006` (breach reports) and `DL-RAN-006` (extortion-group claims).
- The "Not sure" cut rose from 40% to 60% confidence. The hybrid's rule boost, previously an untuned 1.5, is now a measured 8 (synthetic hybrid macro-F1 0.836 to 0.890, chosen on the synthetic test set).
- `label pack|import|agree` bring in extra independent labellers (models or people) and report agreement: four machine labellers reached Fleiss kappa 0.850 on the 300 items (271 agreed, 29 contested); still no human validation.
- `label validate make|check` compares machine-assisted labels with a human sample; `label sheets --since DATE` carves out an untouched test set by fetch date; evaluation files may contain `skip` rows (not scored).
- Fixed: feeds declared as Windows-1252 were decoded as UTF-8, turning apostrophes into replacement characters.

### Added (real-data accuracy toolkit)
- `python -m darklens label pool | sheets | check | split`: gathers public text from security and general RSS feeds (accumulating across runs), writes a private sheet per labeller with a shared overlap, validates the filled sheets with friendly errors, measures inter-labeller agreement (Cohen's and Fleiss' kappa, listing disagreements), and splits the consensus into a tuning half and a locked test half. Labelling files are git-ignored.
- `eval --csv FILE --pipeline`: scores the whole product (alerts, "Not sure", scoring) with missed-threat and false-alarm rates, and reports classes with fewer than 10 examples as "not measured".
- Feed XML is size-capped and DTD/entity declarations are refused.
- Guide for labellers: `docs/labelling.md`.

### Added (after launch)
- **"Not sure" outcome:** when the text model is the only evidence and is under 40% confident, DarkLens no longer attaches a threat label to what is most likely ordinary text. Rule hits, watchlist mentions, leaked credentials and tracker-sourced claims are unaffected.
- **CISA Known Exploited Vulnerabilities** feed (no key) and **URLhaus** malware-link feed (same free abuse.ch key). Both rate Low unless they mention your watchlist; a flaw used by ransomware groups rates Medium.
- Indicator-feed entries now expire after `FEED_RETENTION_DAYS` (default 14), so thousands a day cannot fill a free database.
- Tests can no longer reach the internet or the real on-disk feed cache.

### Changed
- **Found by switching on real data:** ThreatFox adds over a thousand indicators a day. A lone indicator is now capped at Low (it flooded the site with Medium alerts), a listed indicator that mentions your watchlist is now a High or Critical alert (feed items previously ignored the watchlist), the connection map leaves indicator-feed entries out and caps itself at 300 alerts, its layout work is bounded so it cannot freeze a browser, and the Alerts page shows 100 at a time.
- **Ransomware.live terms compliance.** Live collection uses the free PRO API (`RANSOMWARE_LIVE_API_KEY`, sent as `X-API-KEY`) and is skipped without a key. Its claims are shown with a linked attribution, the API never returns their raw text, and they are left out of CSV, STIX and feedback exports. See `docs/data-sources.md`.
- ThreatFox responses are checked by `query_status`, so "no result" and bad-key answers no longer break a run.
- Real ransomware claims were scored Low 90% of the time. They are now recognised from their source and score Medium or High (see `docs/accuracy.md`).
- Adding a watchlist entry now re-scores **all** stored items, not only the demo set.
- `/api/alerts` and the graph load indicators in one query instead of one per alert.
- `/api/eval` is computed once per process.
- `DL-CRD-002` matches "database dump"; `DL-RAN-001` matches "scheduled for publication" and "Deadline: <date>".

### Security
- Pasted text is capped at 20,000 characters, watchlist values are validated server-side, and CSV cells that look like formulas are neutralised.

## [0.1.0] - 2026-11-15

- Initial capstone release: collectors, IOC extraction, rules and classifier, scoring, entity graph, evidence packs, single-page dashboard, FastAPI backend.
