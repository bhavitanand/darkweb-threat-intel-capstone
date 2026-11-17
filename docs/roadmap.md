# Roadmap

Honest status of what exists, what comes next, and what depends on people rather than code. Items are ordered by value for effort.

## Done

| Area | What |
| --- | --- |
| Product | React website (overview, alerts, report, connections, watchlist, check-a-post, get-started guide, how-it-works), mobile friendly, accessible |
| Detection | 27 original rules, hybrid classifier with a "Not sure" cut, noisy-OR scoring with reasons, entity graph and campaigns, ATT&CK mapping, evidence packs, CISA exploited-flaw and URLhaus feeds, a watchlist for domains, emails and software |
| Measurement | A labelling toolkit with multi-labeller agreement (four AI labellers, kappa 0.85 on 300 real items), whole-product scoring, and a first untouched test (see [accuracy](accuracy.md)). All labels are machine-made; no human has validated them |
| Real data | Live Ransomware.live collection on a schedule with per-source status, retention, demo data clearly badged |
| Persistence | Postgres support through `DATABASE_URL` (SQLite stays the zero-setup default) |
| Feedback loop | "Is this right?" votes, labelled export, `eval --feedback`, `eval --csv`, `eval --live-claims` |
| Integrations | CSV and STIX 2.1 export, chat (webhook) and email notifications |
| Safety | Rate limiting, input limits, token-protected ingest, CSV formula protection, CORS allowlist |
| Engineering | 397 backend tests (5 of them only run against a real Postgres, which CI provides) and 22 frontend tests, CI on every push, Dependabot, documented deployment |

## Needs a person (cannot be done by code alone)

| What | Why it matters | Effort |
| --- | --- | --- |
| **Create a free Neon database and set `DATABASE_URL`** | Without it the watchlist and collected data reset whenever the free host restarts | 10 minutes |
| **Get a free Ransomware.live key (<https://my.ransomware.live>) and set `RANSOMWARE_LIVE_API_KEY`** | Their terms require the key. It is what switches on live claims, and it lets us re-measure accuracy on the PRO data | 10 minutes |
| **Optionally ask the Ransomware.live owner for written permission** (<https://ransomware.live/contact>) to show claim text and offer exports | Their terms forbid re-publishing the raw data without it. Without approval, DarkLens shows only titles, our own scores and a link back | An email |
| **Get a free abuse.ch key and set `ABUSECH_AUTH_KEY`** | Switches on ThreatFox and URLhaus indicators | 10 minutes |
| **Optional free keys that would widen the net further** (each needs a new small collector, about an hour once the key exists): AlienVault OTX pulses, VirusTotal and GreyNoise lookups for indicators, Shodan or Censys exposure checks for watched domains, GitHub security advisories (no key, rate limited), the Telegram Bot API for public channels you are allowed to read | More indicator context, exposure of the user's own assets, more early-warning chatter | Key signup plus a collector each |
| **Optional: have one person label the 50-item validation sheet** (`label validate make NAME`) | Every label so far comes from AI labellers that agree with each other (kappa 0.85); this is the one number that says how far to trust them. The team chose to rely on the machine labels for now | 15 minutes |
| **Real examples for the four unmeasured classes** (exploit sales, malware sales, card fraud, chatter) with `label pool --add` | Public news has none, so those classes stay "not measured" until real underground-style text exists | An hour of searching public reports |
| **Review alerts and press "Is this right?"** for a few weeks | Free labelled data and a measure of reviewer agreement | A few minutes a day |
| **Create a chat webhook or SMTP login and set it on the server** | Turns the site from something you check into something that tells you | 15 minutes |
| **Supervisor approval for any live Tor crawling** | The crawler ships disabled by design (see `SECURITY.md`) | Policy decision |

## Next (engineering, about 1 to 3 weeks)

1. ~~Make the classifier admit uncertainty~~ **Done** (see [accuracy](accuracy.md)). Confidently wrong labels remain until the model is retrained on real data.
2. **Retrain on real labelled data.** The first untouched test (17 November) found real breach news missed, which the rules now cover; retraining the classifier itself needs more real threat examples than we have (9 on the untouched set). Then publish real macro-F1 and recalibrate severity thresholds using reviewer feedback.
3. ~~CISA Known Exploited Vulnerabilities and URLhaus~~ **Done.** ~~Watch your software~~ **Done** (17 November). Next source: AlienVault OTX (needs its own free key).
4. **Observability:** structured logs, error tracking (a free Sentry plan), and a public status line.
5. ~~Pagination and server-side filtering~~ **Done** (17 November): the API pages and filters in the database (`offset`, `X-Total-Count`) and the Alerts page uses it, so the count is the true total.
6. **A second untouched test** from items collected after 17 November, labelled the same way, scored once before any change.
7. **Daily or weekly email digest** of what changed.

## Later (1 to 3 months)

1. **Accounts and private workspaces.** Today the watchlist is shared by every visitor (stated on the Watchlist page). Per-organisation workspaces, sign-in (for example magic links) and API keys are the biggest step toward a real product, and the prerequisite for confidential watchlists.
2. **A model comparison:** fine-tune a small transformer (DistilBERT) on the real labelled set and compare it with TF-IDF honestly.
3. **Standards:** a TAXII endpoint and MISP export so DarkLens plugs into existing tooling.
4. **Security hardening:** CodeQL scanning, security headers, a written threat model, an independent review.
5. **Release discipline:** version tags, a published container image, and a changelog entry per release.
6. **Background job queue** for ingestion and notifications if one worker stops being enough.

## Will not do

- Logging in to markets or forums, buying anything, or contacting sellers.
- Storing plaintext passwords, leaked files, or full pages.
- Claiming that a score proves a breach. A score is a guide to where to look first.

## How the project is run

- `main` is deployed automatically. CI must pass before merging.
- Every change that alters behaviour gets a test and a line in [CHANGELOG.md](../CHANGELOG.md).
- Accuracy claims in the docs must name the data they were measured on.
