"""The labelling policy as prompts, so every independent labeller (a person or a model) works from the same rules.

Two versions: the full policy, and a simpler step-by-step one for weaker models that get confused by long rules.
"""
from __future__ import annotations

LABELS = ["ransomware_leak", "credential_dump", "exploit_sale", "phishing_kit", "malware_sale", "carding_fraud",
          "threat_chatter", "benign", "skip"]

# Words a model (or a tired person) is likely to write instead of the exact label. Anything not here is rejected, never guessed.
ALIASES = {
    "ransomware": "ransomware_leak", "ransomware_leaks": "ransomware_leak", "extortion": "ransomware_leak", "leak": "ransomware_leak",
    "credential": "credential_dump", "credentials": "credential_dump", "breach": "credential_dump", "data_breach": "credential_dump",
    "credential_dumps": "credential_dump", "data_leak": "credential_dump",
    "exploit": "exploit_sale", "exploits": "exploit_sale", "access_sale": "exploit_sale", "exploit_for_sale": "exploit_sale",
    "phishing": "phishing_kit", "phishing_kits": "phishing_kit",
    "malware": "malware_sale", "malware_for_sale": "malware_sale",
    "carding": "carding_fraud", "fraud": "carding_fraud", "card_fraud": "carding_fraud",
    "chatter": "threat_chatter", "threat": "threat_chatter",
    "not_a_threat": "benign", "none": "benign", "normal": "benign", "ordinary": "benign", "safe": "benign",
    "other": "skip", "unclear": "skip", "unsure": "skip", "not_sure": "skip", "unknown": "skip", "cant_tell": "skip",
}

SIMPLE_PROMPT = """You will label short news items. Answer EVERY item with ONE label. Follow the steps in order.

STEP 1. Is the item about a cyberattack, hack, stolen or leaked data, malware, or a scam?
  NO  -> label: benign   (this is most items: general news, science, sport, business, tech products, advice, patch notices)
  YES -> go to step 2.

STEP 2. Pick the FIRST that fits:
  - A ransomware or extortion group, a ransomware attack, or a leak site          -> ransomware_leak
  - Personal, customer or employee data stolen, leaked or put up for sale (breach) -> credential_dump
  - Someone SELLING an exploit, a zero-day, or access to a network                  -> exploit_sale
  - A phishing kit or fake login pages for sale                                    -> phishing_kit
  - Malware that is being SOLD or RENTED                                           -> malware_sale
  - Stolen bank cards or card fraud shops                                          -> carding_fraud
  - Hackers boasting or planning attacks (DDoS, defacement), nothing sold          -> threat_chatter
  - Anything else about an attack (a flaw being exploited, a spy group, a malware analysis,
    police taking servers down, a company saying it had a "cyber incident")         -> skip

EXAMPLES
  "Spacecraft launches to bring back Mars moon dust"                              -> benign
  "Microsoft fixes 1,000 security flaws this month"                               -> benign
  "How to spot a tax scam"                                                        -> benign
  "Extortion group claims it stole a billion travel records"                      -> ransomware_leak
  "University says personal information was stolen in a cyberattack"              -> credential_dump
  "Selling remote access to a US telecom, price 2 BTC"                            -> exploit_sale
  "Researchers analyse a new Android spyware"                                     -> skip
  "Hackers exploit a flaw in a chat server"                                       -> skip

Use only these words: benign, ransomware_leak, credential_dump, exploit_sale, phishing_kit, malware_sale,
carding_fraud, threat_chatter, skip.

ANSWER FORMAT: one line per item, exactly like this, with no other text, no explanations and no table:
1: benign
2: skip
3: credential_dump

Here are the items:
"""

FULL_PROMPT = """You are an independent annotator for a text-classification evaluation. Label each numbered news item
(a headline plus a short summary) with exactly ONE label. Work only from this policy and your own judgement.

Output format, one line per item, nothing else: number<TAB>label<TAB>unsure
where `unsure` is 1 if you hesitated between two labels, otherwise 0. All numbers must be present, in order.
Use only these exact label words.

LABELS (label what kind of threat the text is about):
- ransomware_leak: an organisation hit by ransomware, a leak-site posting, an extortion countdown; an extortion or
  ransomware group claiming a victim; a report on a ransomware incident or on ransomware leak-site activity.
- credential_dump: stolen logins, a leaked user database, combo lists or stealer logs offered, shared or reported;
  personal, customer or employee data stolen, leaked or put up for sale (a breach report).
- exploit_sale: someone SELLING an exploit, a zero-day, or access into a network.
- phishing_kit: fake login pages, phishing toolkits or phishing-as-a-service on offer or described in detail.
- malware_sale: malware (stealers, RATs, loaders, botnets, crypters) OFFERED or RENTED.
- carding_fraud: stolen payment cards, carding shops, cash-out and fraud services.
- threat_chatter: planning or boasting about attacks (DDoS, defacement, hacktivism) without a sale or stolen data.
- benign: not about a threat at all, or advice, product launches, opinion, general news, a patch or vulnerability
  notice with no sale or incident, security roundups and podcasts, scam-awareness advice.
- skip: security attack or exploitation news that fits none of the classes above (an exploited vulnerability, an
  espionage/APT report, a malware analysis, a law-enforcement takedown, a company confirming an unspecified cyber
  incident, a supply-chain compromise report) OR text you cannot judge. `skip` is not scored.

Rules of thumb: if two labels fit, choose the main point of the text. A vulnerability or patch advisory with no sale
and no incident is benign; a report of exploitation in the wild or a malware analysis is skip. Do not search the web.
Be consistent, and think item by item: this is a measurement task, so accuracy matters more than speed.
"""
