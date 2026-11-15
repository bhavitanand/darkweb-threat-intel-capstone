# Security, ethics and responsible use

DarkLens is a defensive research project. These rules apply to everyone who contributes or runs it.

## What the code enforces
- **Allowlist crawler.** `darklens/crawler/tor.py` refuses any host not listed in `allowlist.yaml` (empty by default), is GET-only, text-only, rate limited, keeps snippets of at most 600 characters, and stops if a file named `STOP_CRAWL` exists. The default mode is a dry run.
- **No plaintext passwords stored.** Email:password pairs are masked before anything is written to the database, and exposure results only contain a masked password and a 5-character hash prefix.
- **k-anonymity for password checks.** Only the first 5 characters of a SHA-1 hash ever leave the machine (Pwned Passwords range API).
- **Synthetic demo data.** Everything in `data/samples/` is fictional. No real leaked data is included in this repository.

## What contributors must do
1. Never log in, register, buy, message sellers, or download leaked files.
2. Run any live Tor crawling only from a disposable VM or container, never from a personal machine.
3. Add a host to the allowlist only after your supervisor has approved it.
4. Never commit real credentials, real victim data, or API keys. Use environment variables (`ABUSECH_AUTH_KEY`, `HIBP_API_KEY`).
5. If you find a live leak naming a real organisation, do not test or contact it yourself. Tell your supervisor.
6. Respect each source's terms: Ransomware.live is non-commercial with attribution and a 30-minute cache; abuse.ch needs its free key and fair use.

## Reporting a problem
Open a private security advisory on this repository or contact the maintainers directly.
