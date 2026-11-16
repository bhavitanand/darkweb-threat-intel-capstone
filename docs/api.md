# API reference

Base URL: your Render address (or `http://127.0.0.1:8000` locally). Interactive docs are served at `/docs`. All responses are JSON unless noted. There are no accounts: reads are open, and heavier actions are rate limited (see [deployment](deployment.md)). A limited client receives `429` with a `Retry-After` header.

## Read

| Method and path | Returns |
| --- | --- |
| `GET /api/health` (also `HEAD`) | `{ok, version, storage}`. Never rate limited. |
| `GET /api/stats` | Counts by severity, category and indicator type, plus `real_alerts` and `demo_alerts` |
| `GET /api/alerts?severity=&category=&q=&limit=` | Alerts, highest score first. `limit` defaults to 1000, maximum 5000. Each has `demo`, `signals`, `iocs` |
| `GET /api/alerts/{id}` | One alert with `mitre` techniques and `feedback` counts |
| `GET /api/alerts/{id}/evidence` | HTML evidence pack (sealed with a SHA-256 hash) |
| `GET /api/graph` | Entity graph (`nodes`, `links`), `linked_actors`, `campaigns` |
| `GET /api/watchlist` | Watched domains and emails |
| `GET /api/eval` | Model scores on the synthetic test set (cached per process) |
| `GET /api/ingest/status` | Last collection: time, mode (`live` or `demo`), per-source status, `auto_ingest_minutes` |
| `GET /api/feedback/summary` | Reviewer feedback: total, agreement, and which corrections were made |

## Exports

| Method and path | Returns |
| --- | --- |
| `GET /api/export/alerts.csv` | Spreadsheet-safe CSV of all alerts |
| `GET /api/export/stix.json` | STIX 2.1 bundle (`application/stix+json`) |
| `GET /api/export/feedback.csv` | Labelled examples from reviewer feedback (`text,label,predicted,item_id`) |

## Write

| Method and path | Body | Notes |
| --- | --- | --- |
| `POST /api/watchlist` | `{kind: "domain" or "email", value}` | Validated. Re-scores everything stored, then sends any pending notifications |
| `POST /api/analyse` | `{text (max 20000 chars), title}` | Scores pasted text. Nothing is stored |
| `POST /api/alerts/{id}/feedback` | `{verdict: "correct" or "wrong", category}` | `category` is required when `wrong` and must differ from the current one. One vote per visitor per alert (a later vote replaces it) |
| `POST /api/ingest?offline=false` | none | Runs a collection now. Needs header `X-Ingest-Token` if `INGEST_TOKEN` is set. `offline=true` (default) loads demo data |

## Errors

`400` invalid input (the `detail` says what), `401` missing ingest token, `404` unknown alert, `422` body too large or malformed, `429` too many requests.
