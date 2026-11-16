# Security, ethics and responsible use

DarkLens is a defensive research project. These rules apply to everyone who contributes or runs it.

## What the code enforces
- **Allowlist crawler.** `darklens/crawler/tor.py` refuses any host not listed in `allowlist.yaml` (empty by default), is GET-only, text-only, rate limited, keeps snippets of at most 600 characters, and stops if a file named `STOP_CRAWL` exists. The default mode is a dry run.
- **No plaintext passwords stored.** Email:password pairs are masked before anything is written to the database, and exposure results only contain a masked password and a 5-character hash prefix.
- **k-anonymity for password checks.** Only the first 5 characters of a SHA-1 hash ever leave the machine (Pwned Passwords range API).
- **Synthetic demo data.** Everything in `data/samples/` is fictional. No real leaked data is included in this repository.
- **Live mode stores only public claims, and respects the source's terms.** When live collection is on, the database holds short titles and snippets of public ransomware claims (including the named organisation), never leaked files, full pages or credentials. Ransomware.live's terms forbid re-publishing its raw data, so the API never returns that text and such items are left out of every export, and the source is credited with a link. See `docs/data-sources.md`. An organisation that wants an entry removed can open a "takedown" issue.
- **Open API, rate limited.** There are no accounts. Reads are open, writes are rate limited, pasted text and watchlist values are size-limited and validated, `POST /api/ingest` can be locked with `INGEST_TOKEN`, and CSV exports neutralise spreadsheet formulas. The watchlist is shared by every visitor, so it must not hold confidential information.
- **Secrets stay in the environment.** `DATABASE_URL`, webhook URLs, SMTP passwords and API keys are read from environment variables, are never logged or sent in messages, and must never be committed.

## What contributors must do
1. Never log in, register, buy, message sellers, or download leaked files.
2. Run any live Tor crawling only from a disposable VM or container, never from a personal machine.
3. Add a host to the allowlist only after your supervisor has approved it.
4. Never commit real credentials, real victim data, or API keys. Use environment variables (`ABUSECH_AUTH_KEY`, `HIBP_API_KEY`).
5. If you find a live leak naming a real organisation, do not test or contact it yourself. Tell your supervisor.
6. Respect each source's terms: Ransomware.live needs its free API key, is non-commercial with a linked attribution and a 30-minute cache, and forbids re-serving or publishing its raw data; abuse.ch needs its free key and fair use. Read the terms before adding a source or an export.

## Reporting a problem
Open a private security advisory on this repository or contact the maintainers directly.
