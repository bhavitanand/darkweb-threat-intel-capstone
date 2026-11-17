# API reference

Base URL: your Render address (or `http://127.0.0.1:8000` locally). Interactive docs are served at `/docs`. All responses are JSON unless noted. There are no accounts: reads are open, and heavier actions are rate limited (see [deployment](deployment.md)). A limited client receives `429` with a `Retry-After` header.

## Read

| Method and path | Returns |
| --- | --- |
| `GET /api/health` (also `HEAD`) | `{ok, version, storage}`. Never rate limited. |
| `GET /api/stats` | Counts by severity, category and indicator type, plus `real_alerts` and `demo_alerts` |
| `GET /api/alerts?severity=&category=&q=&data=&limit=&offset=` | Alerts, highest score first. Filters (`severity`, `category`, text `q`, and `data` = `real` or `demo`) are applied in the database before paging. `limit` defaults to 1000, maximum 5000; `offset` pages through. The header `X-Total-Count` is how many alerts match the filters. Each alert has `demo`, `signals`, `iocs`. Text a source forbids re-publishing is neither returned nor searchable |
| `GET /api/alerts/{id}` | One alert with `mitre` techniques and `feedback` counts |
| `GET /api/alerts/{id}/evidence` | HTML evidence pack (sealed with a SHA-256 hash) |
| `GET /api/graph` | Entity graph (`nodes`, `links`), `linked_actors`, `campaigns` |
| `GET /api/watchlist` | Watched domains, emails and software or vendor names |
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
| `POST /api/watchlist` | `{kind: "domain", "email" or "product", value}` | Validated (a product is a name such as `screenconnect`, 3 to 60 characters). Re-scores the stored items that mention the new entry, then sends any pending notifications. The shared list holds at most 100 entries (`400` when full) |
| `POST /api/analyse` | `{text (max 20000 chars), title}` | Scores pasted text. Nothing is stored. Only the first 5,000 characters are classified; indicators and watchlist matches search all of it, and the answer has `truncated: true` when the text was cut |
| `POST /api/alerts/{id}/feedback` | `{verdict: "correct" or "wrong", category}` | `category` is required when `wrong` and must differ from the current one. One vote per visitor per alert (a later vote replaces it) |
| `POST /api/ingest?offline=false` | none | Runs a collection now. `offline=true` (default) loads demo data and is open unless `INGEST_TOKEN` is set. `offline=false` (live) is refused with `403` unless `INGEST_TOKEN` is set on the server, and then needs the header `X-Ingest-Token`. Scheduled collection (`AUTO_INGEST_MINUTES`) does not use this endpoint |

## Errors

`400` invalid input (the `detail` says what), `401` missing ingest token, `404` unknown alert, `422` body too large or malformed, `429` too many requests.
