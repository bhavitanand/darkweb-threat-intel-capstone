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

### Changed
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
