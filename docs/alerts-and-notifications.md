# Alerts, notifications and exports

## Notifications

DarkLens can message you when something about your watchlist appears. It is off unless you configure a channel, using environment variables on the server (never in the website, and never committed to Git).

### Chat (Slack, Discord, Teams, or anything that accepts a JSON POST)

```
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
PUBLIC_APP_URL=https://your-site.vercel.app     # optional: adds a link to each message
```

Create an incoming webhook in your chat tool and paste its URL. The message is sent as `{"text": ..., "content": ...}` so Slack and Discord both read it.

### Email (SMTP)

```
SMTP_HOST=smtp.example.com
SMTP_PORT=587                  # 587 uses STARTTLS (default)
SMTP_USER=...
SMTP_PASSWORD=...
ALERT_EMAIL_TO=you@example.com
ALERT_EMAIL_FROM=darklens@example.com   # optional
```

### What triggers a message

`NOTIFY_MIN` controls it:

| Value | Sends a message for |
| --- | --- |
| `watchlist` (default) | Alerts about your own domains or emails only |
| `critical` | The above, plus every Critical alert |
| `high` | The above, plus every High alert |

Rules that always apply:

- Each alert is sent **once** per channel.
- Demo data never sends anything (set `NOTIFY_DEMO=1` only to test).
- One collection run sends at most 10 messages, then a single "N more are waiting" summary.
- If a channel is down, the alert stays pending and is retried on the next run.
- A message contains the severity, score, title, the main reason, and a link. It never contains passwords or secrets.

Test your setup from a shell that has the variables set:

```bash
python -m darklens notify-test
```

## Exports

| What | Where | Use it for |
| --- | --- | --- |
| Alerts as CSV | Alerts page, or `GET /api/export/alerts.csv` | Spreadsheets. Cells that start with `=`, `+`, `-` or `@` are prefixed so a spreadsheet never runs them as formulas. |

**Exports leave out Ransomware.live claims.** Its terms do not allow its data to be re-published "via API, file, or otherwise", so those alerts are never in the CSV, STIX or feedback downloads (see [data sources](data-sources.md)). Demo data and sources that allow sharing are included. The table:

| Alerts as STIX 2.1 | Alerts page, or `GET /api/export/stix.json` | Importing into other threat-intelligence tools. Contains reports, indicators and vulnerabilities. Crypto wallets (no STIX standard type) are carried in `x_darklens_wallets` on each report. |
| Reviewer feedback as CSV | `GET /api/export/feedback.csv` | Labelled data for measuring accuracy. |
| Evidence pack | Alert report, "Open evidence pack" | A sealed, self-contained page for one alert, to share or keep. |
