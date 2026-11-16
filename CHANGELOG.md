# Changelog

All notable changes. Dates are when the change was made.

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
