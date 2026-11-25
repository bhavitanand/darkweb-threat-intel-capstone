# Threat model

What we protect, who might attack it, and what stops them. Written for v0.3; update it whenever a feature changes who can send what to whom.

## What is worth protecting
| Asset | Why it matters |
| --- | --- |
| Visitors' private watchlists (domains, emails, products) | They reveal what an organisation fears or runs |
| Sign-in links, session tokens, API keys | Anyone holding one acts as that person |
| Text from sources that forbid re-publishing | A leak breaks their terms |
| Availability of the free-tier API | One visitor must not take the site down for others |
| Our own outbound requests (webhooks, feeds, email) | They must not be turned against third parties or our own network |

## Who might attack, and how
| Threat | Control |
| --- | --- |
| Guessing or replaying a sign-in link | 256-bit random token, stored only as a hash, one use, 15 minutes, 5 requests per address per hour; the response is identical for any address so it cannot be used to find who has an account |
| Stealing a session or API key from the database | Only hashes are stored; keys are shown once; sessions expire after 30 days, at most 10 per person; deleting the account removes everything |
| Reading another person's workspace | Every workspace query is keyed by the signed-in user's own workspace id taken from the session, never from the request; tests sign in as two users and try to cross over |
| Webhook abuse (SSRF: making the server call internal addresses) | https only, host must resolve to a public address, checked again at send time, no redirects followed, short timeout, at most 10 sends per run |
| Pointing a connector at someone else's service (v0.4) | Each connector only accepts its own service's addresses (hooks.slack.com, discord.com/api/webhooks, webhook.office.com, logic.azure.com, powerplatform.com), on top of every webhook check above |
| Reading a connector address back (it lets anyone post to that channel) | The API returns it masked (first 32 and last 4 characters); only the owner's workspace can test or remove it |
| Hostile alert rules (v0.4) | Prompts are capped at 300 characters, a spec edited in the browser is cleaned on the server (known keys only, sizes and patterns checked), at most 20 rules each, and the parser has no unbounded patterns; `POST /api/rules/parse` stores nothing and counts against the read rate limit |
| Header or log injection through titles, names or webhook text | Control characters are stripped before anything is sent or logged; spreadsheet formulas are neutralised in CSV |
| Regular-expression denial of service | Every pattern is bounded; 20,000-character inputs are timed in tests |
| Spamming sign-in emails to a victim | Per-address hourly cap plus per-client write rate limit |
| Flooding the free-tier API | Per-client rate limits (reads and writes), size limits on every body, paging limits |
| Triggering a live collection | `POST /api/ingest` live mode refused unless `INGEST_TOKEN` is set; compared in constant time |
| Reading hidden source text through search or export | Such text is excluded in the database query, not just hidden in the UI; tests on real data enforce it |
| Poisoned feeds (malformed or hostile data from a source) | Collectors treat every field as untrusted: type-checked, length-capped, one bad item never stops a run |
| Clickjacking, sniffing, third-party tracking | Security headers on the site, bundled fonts, no third-party requests from the browser |
| Vulnerable dependencies or code | CI tests, CodeQL (Python and TypeScript) on every push and weekly |

## Known limits (not defended, said plainly)
- **One server process.** Rate limits and caches live in memory, so they reset on restart and do not span several workers.
- **Email is the identity.** Anyone who controls an inbox controls the account; there is no second factor.
- **The public alert feed is open to everyone.** Only private workspace features sit behind sign-in.
- **A compromised host** (Render, Vercel, Neon) would expose what we store. We keep as little as we can: no passwords, no plaintext keys, masked credentials, short snippets.
- **The shared public watchlist** is writable by any visitor (capped, validated, rate limited) and must never hold confidential data; private lists belong in a workspace.
