"""Synthetic labelled corpus generator.

IMPORTANT: this data is SYNTHETIC. It is generated from hand-written templates with random fills,
and contains no real leaked data. It exists so the classifier can be trained, evaluated and demoed
without touching illegal content. Evaluation uses held-out TEMPLATES (unseen sentence structures),
not just held-out rows, to avoid flattering the model. See README "Honest limitations".
"""
from __future__ import annotations

import random

CATEGORIES = [
    "ransomware_leak", "credential_dump", "exploit_sale", "phishing_kit",
    "malware_sale", "carding_fraud", "threat_chatter", "benign",
]

COMPANIES = ["Northwind Logistics", "Acme Textiles", "Bluepeak Hospital", "Orbit Telecom", "Granite Bank",
             "Helios Energy", "Maple Retail", "Zenith Pharma", "Cedar Municipal Council", "Atlas Freight"]
BRANDS = ["Office365", "PayPal", "Netflix", "DHL", "Dropbox", "HDFC", "Amazon", "Paytm"]
MALWARE = ["RAT", "loader", "crypter", "stealer", "botnet panel", "keylogger"]
SIZES = ["120 GB", "2.4 TB", "800 MB", "45 GB", "1.1 TB", "300 GB"]
ROWS = ["1.2 million", "480k", "7.9 million", "260,000", "3 million"]
PRODUCTS = ["Citrix", "Fortinet VPN", "Exchange", "Confluence", "a router firmware", "a CMS plugin"]
PRICES = ["$300", "0.05 BTC", "$1,500", "2 XMR", "$80 lifetime"]
SECTORS = ["bank", "hospital", "telecom", "retail", "energy", "government"]

# Each category has templates split into TRAIN and TEST sets (different sentence structures).
TEMPLATES: dict[str, dict[str, list[str]]] = {
    "ransomware_leak": {
        "train": [
            "{co} has been hacked. {size} of data will be published in 5 days unless they contact us.",
            "New victim: {co}. We exfiltrated {size} including finance and HR files. Countdown started.",
            "Your network is encrypted and your data is stolen. Chat with support to negotiate the ransom.",
            "{co} refused to pay. Proofs uploaded. Full leak of {size} follows at the deadline.",
            "Affiliate program open, 80/20 split, locker for Windows and ESXi. Recruiting experienced pentesters.",
        ],
        "test": [
            "Attention {co} management: decryption keys are available after payment, otherwise your documents go public.",
            "Case update for {co}: negotiation stalled, {size} dump scheduled for release.",
            "RaaS panel now accepting new partners, we handle negotiation and the leak blog.",
        ],
    },
    "credential_dump": {
        "train": [
            "Selling database dump of {co}, {rows} rows, emails and bcrypt hashes, fresh breach.",
            "Fresh stealer logs from Redline, cookies and saved passwords, {rows} lines, daily cloud.",
            "Combolist {rows} lines email:password high quality private not public.",
            "Corporate VPN logins for {co} employees, tested valid this week.",
        ],
        "test": [
            "Leaked users table from {co}, {rows} accounts, md5 hashed, sample in thread.",
            "Infostealer cloud subscription, Lumma and Vidar logs sorted by country and domain.",
            "Admin credentials and customer logins for a {sector} company, price {price}.",
        ],
    },
    "exploit_sale": {
        "train": [
            "Selling 0day RCE for {prod}, working poc and writeup, price {price}.",
            "CVE-2025-{n} weaponized exploit available, bypasses authentication, escrow accepted.",
            "Initial access: RDP into a {sector} company, domain admin, revenue 200M, price {price}.",
            "Zero-day local privilege escalation Windows, full chain, serious buyers only.",
        ],
        "test": [
            "Access broker listing: VPN foothold at {co}, {price}, escrow via admin.",
            "Looking to sell a working exploit for {prod}, remote code execution, no user interaction.",
            "Privilege escalation poc for sale, exploit tested on latest patch level, DM for price {price}.",
        ],
    },
    "phishing_kit": {
        "train": [
            "{brand} phishing kit with admin panel, anti-bot and cloaking, updated weekly, {price}.",
            "Phishing page template for {brand} login, 2FA relay supported, hosted letters panel.",
            "Selling scam page bundle, bank clones, otp intercept, telegram bot logs.",
        ],
        "test": [
            "Fresh {brand} login clone with evilginx phishlet, bypasses mfa, install guide included.",
            "Phishing panel subscription: victim logs, geo filter, hides from scanners, {price}.",
            "New kit drop, {brand} and {brand} templates, built-in antibot, price {price}.",
        ],
    },
    "malware_sale": {
        "train": [
            "{mal} for sale, FUD, lifetime licence {price}, bypasses Defender and EDR.",
            "Selling private {mal}, undetected by antivirus, builder and support included, {price}.",
            "New botnet, 20k bots, subscription {price}, loader with persistence.",
        ],
        "test": [
            "Offering a custom {mal} that evades CrowdStrike and SentinelOne, tested, {price}.",
            "Crypter service, undetected on all major AV, monthly {price}, escrow ok.",
            "Keylogger and rootkit bundle, kernel driver signed, price {price}.",
        ],
    },
    "carding_fraud": {
        "train": [
            "Fresh cvv and fullz shop, filter by BIN and country, instant checker, {price}.",
            "Dumps with pin, track data, cashout guide, mules wanted in EU.",
            "Drops needed for parcel reshipping, good payout, cash out the same day.",
        ],
        "test": [
            "Credit cards from {sector} breach, fullz with ssn, bin list updated daily.",
            "Looking for mules to move funds, cashout service available, trusted sellers only.",
            "CC checker tool and shop access, new bins added, price {price}.",
        ],
    },
    "threat_chatter": {
        "train": [
            "We will attack {sector} sector targets next month, collective is recruiting for ddos.",
            "Planning a defacement and ddos campaign against government sites, join channel.",
            "I plan to target a {sector} next, anyone with access ideas please message.",
        ],
        "test": [
            "Operation announced: our group is going to breach telecom providers this quarter.",
            "Hacktivist call to arms, targets are retail and energy, tools shared in the channel.",
            "Anyone already inside a {sector}? We are looking to hit them before month end.",
        ],
    },
    "benign": {
        "train": [
            "Looking for recommendations on a good privacy-focused email provider, thanks.",
            "How do I set up Tor browser on Linux and keep it updated?",
            "Weekly thread: what books are you reading about cryptography and security history?",
            "Which VPN do journalists use for safe reporting? Looking for a review comparison.",
            "Anyone tried the new open source password manager? Feedback on setup welcome.",
        ],
        "test": [
            "Tutorial: setting up a home lab with virtual machines to practice defensive security.",
            "Discussion about the history of the cypherpunk movement and public key cryptography.",
            "Need help configuring a secure messenger for my family, what do you recommend?",
            "Meetup announcement: a talk on safe browsing habits and phishing awareness for beginners.",
        ],
    },
}

NOISE = ["thanks", "dm me", "serious only", "no timewasters", "see you", "bump", "thread updated", "wait, one more thing"]


def _fill(tpl: str, rng: random.Random) -> str:
    out = tpl.format(
        co=rng.choice(COMPANIES), size=rng.choice(SIZES), rows=rng.choice(ROWS), brand=rng.choice(BRANDS),
        mal=rng.choice(MALWARE), prod=rng.choice(PRODUCTS), price=rng.choice(PRICES), sector=rng.choice(SECTORS),
        n=rng.randint(1000, 9999),
    )
    if rng.random() < 0.5:
        out += " " + rng.choice(NOISE)
    return out


def generate(split: str, per_template: int = 12, seed: int = 7) -> tuple[list[str], list[str]]:
    rng = random.Random(seed if split == "train" else seed + 1)
    texts, labels = [], []
    for cat, parts in TEMPLATES.items():
        for tpl in parts[split]:
            for _ in range(per_template):
                texts.append(_fill(tpl, rng))
                labels.append(cat)
    return texts, labels
