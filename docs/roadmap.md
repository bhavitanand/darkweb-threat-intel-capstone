# Roadmap

Honest status of what exists, what comes next, and what depends on people rather than code. Items are ordered by value for effort.

## Versions

| Version | Released | Theme |
| --- | --- | --- |
| 0.1.0 | 2026-11-15 | Core engine and API |
| 0.2.0 | 2026-11-16 | Website, live data, feedback, exports, CI |
| 0.2.1 | 2026-11-17 | Real-data training and testing, wider net, hardening |
| 0.3.0 | 2026-11-23 | Accounts, workspaces, standards, more sources, observability |
| 0.4.0 | 2026-11-25 | Redesign, sign-in first, alerts written as sentences, My alerts, Connectors, readable Connections |
| 1.0.0 | not scheduled | See "What 1.0 means" below |

Full detail for each is in the [changelog](../CHANGELOG.md).

## Done

| Area | What |
| --- | --- |
| Product | React website (overview, alerts, report, connections, watchlist, check-a-post, get-started guide, how-it-works), mobile friendly, accessible |
| Detection | 27 original rules, hybrid classifier with a "Not sure" cut, noisy-OR scoring with reasons, entity graph and campaigns, ATT&CK mapping, evidence packs, CISA exploited-flaw and URLhaus feeds, a watchlist for domains, emails and software |
| Measurement | A labelling toolkit with multi-labeller agreement (four AI labellers, kappa 0.85 on 300 real items), whole-product scoring, and a first untouched test (see [accuracy](accuracy.md)). All labels are machine-made; no human has validated them |
| Real data | Live Ransomware.live collection on a schedule with per-source status, retention, demo data clearly badged |
| Persistence | Postgres support through `DATABASE_URL` (SQLite stays the zero-setup default) |
| Feedback loop | "Is this right?" votes, labelled export, `eval --feedback`, `eval --csv`, `eval --live-claims` |
| Accounts (v0.3) | Sign-in by emailed one-time link, private workspaces with their own watchlist and alert feed, email digest, per-workspace webhook, API keys, account deletion |
| Integrations | CSV, STIX 2.1 and MISP export, a read-only TAXII 2.1 server, chat (webhook) and email notifications, GitHub advisories as a source, indicator lookups through OTX, VirusTotal and GreyNoise when their keys are set |
| Safety | Rate limiting, input limits, token-protected ingest, CSV formula protection, CORS allowlist |
| Engineering | 877 backend tests (5 of them only run against a real Postgres, which CI provides) and 97 frontend tests, CI on every push, CodeQL, Dependabot, optional Sentry, a written [threat model](threat-model.md), documented deployment |

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

## v0.3 plan: two tracks, run together

The pitch rests on accuracy; the product is what makes people use it. v0.3 does both, in parallel, because they share almost no code. "Done" for v0.3 means every item below is either finished or has a written reason.

### Track A: accuracy (make the numbers true for every class, not only breaches)

Today three of the eight classes are measured on real text (breach, ransomware once the key is set, plus the false-alarm rate on ordinary text). The rest have no real examples, so no score may be quoted for them.

| # | Item | Who | Done when |
| --- | --- | --- | --- |
| A1 | **A second untouched test**: collect items first seen after 17 November, label them with the same four AI labellers, score once without tuning | Dev, plus the browser steps | A published result, and the set marked spent |
| A2 | **Real examples for the unmeasured classes**: exploit sale, malware sale, card fraud, threat chatter, phishing kit. Sources that are allowed: public researcher and vendor write-ups of real underground listings (with quoted listing text), law-enforcement takedown notices, Telegram public-channel text through the Bot API where reading it is permitted, and any crawler data once a supervisor approves the allowlist | A teammate collects, then it is labelled and loaded | 30 or more real examples per class, kept separate from training |
| A3 | **Score each class on real text and publish it**, including the classes where it is poor | Dev | `docs/accuracy.md` has a per-class table of real results with sample sizes |
| A4 | **Retrain on the larger real set** and keep the honest protocol (train earlier, test later) | Dev | Held-out per-class scores, with a CI gate for each class that has enough data |
| A5 | **Calibrate severity** (breaches are conservative: 82% reach Medium) using reviewer feedback and the labelled sets | Dev, with feedback from the team | Severity bands checked against labelled examples |
| A6 | **A human check on a sample** of the AI labels (the one number that says how far to trust them). Optional and only when someone has 15 minutes | Any teammate | One human-versus-machine kappa |
| A7 | **Model comparison**: fine-tune a small transformer (DistilBERT) on the real set and compare with TF-IDF on the same split | Dev | A side-by-side table; keep whichever is better and cheaper to run |

### Track B: product (make it something people keep using)

| # | Item | Who | Done when |
| --- | --- | --- | --- |
| B1 | **Accounts and private workspaces**: sign-in by emailed magic link, a watchlist per workspace, API keys. The shared public watchlist stays as a read-only demo | Dev builds, the team creates the email sender (Brevo or SMTP) | A new visitor can sign in, add a private watchlist, and cannot see anyone else's |
| B2 | **Daily or weekly email digest** of what changed for that workspace's watchlist, with unsubscribe | Dev | A real digest arrives and only contains that workspace's matches |
| B3 | **Alerts that reach people**: Slack, Discord and WhatsApp (the WhatsApp bot from the E-TAP project is the same pattern), chosen per workspace | Dev, using the existing webhooks | One alert delivered on each channel in a test |
| B4 | **More sources with free keys**: AlienVault OTX, VirusTotal and GreyNoise lookups for indicators, GitHub security advisories | A teammate signs up for each key, Dev writes a collector for each | Each appears in the status card |
| B5 | **Exposure checks for your own assets**: given a watched domain, check public exposure through Shodan or Censys | A teammate gets the key, then it is built | A watched domain shows what it exposes publicly |
| B6 | **Observability**: structured logs, Sentry, and a public status line | A teammate creates the Sentry project, Dev wires it | An error appears in Sentry and the site shows its own health |
| B7 | **Standards**: TAXII endpoint and MISP export | Dev | An external tool can pull the feed |
| B8 | **Hardening and releases**: CodeQL, a written threat model, a version tag and published container image per release, a background job queue if one worker stops being enough | Dev | Tagged `v0.3.0` with the changelog |

**Status on 2026-11-23:** B1, B2, B3 (Slack, Discord and Teams webhooks; WhatsApp not yet), B6 (the Sentry hook is in, waiting for your DSN), B7 and the code and docs parts of B8 (CodeQL, threat model) are built and tested. Still to do: B4 and B5 (need your keys), B8's tag and container image, and Track A items that need new data or a GPU.

### Order

1. **This week:** confirm the deploy and CI, set the Render and abuse.ch keys, then A1 and A2 start (they are slow because they depend on collecting data).
2. **Then, in parallel:** A3 to A5 as the data arrives; B1 and B2 (the longest product items), then B3.
3. **Last:** B4 to B8 and A7 as time allows, and the `v0.3.0` tag.

### What only a person can do

Keys and accounts (OTX, VirusTotal, GreyNoise, Shodan or Censys, Sentry, an email sender), supervisor approval for anything that reads non-public sources, collecting the real underground-style text for A2, and an optional human check for A6.

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

## What 1.0 means

Version 1.0 is a promise, not a date. It needs all of these:

1. **Accuracy measured on every class with real text**, including a second untouched test and a human-checked sample of the labels (items A1 to A3, plus the optional human check).
2. **A stable API** that is versioned, so people can build on it without breaking.
3. **Sign-in with more than an inbox** (a second factor or a social login), and a shared job queue so more than one server process is safe.
4. **Keys-dependent sources live** (Ransomware.live, abuse.ch, OTX, VirusTotal, GreyNoise, Shodan or Censys) and their terms honoured on the page.
5. **An independent look at security**: the CodeQL and threat-model work in 0.3, then an outside review.

Until these are true the version stays below 1.0.
