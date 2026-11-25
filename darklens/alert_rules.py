"""Alert rules written as a sentence: "alert me for any PHP to shell vulnerability in WordPress".

A local, rule-based parser turns the sentence into a small, editable spec. It does not call an AI service, so it works
offline, costs nothing, and does exactly the same thing every time. The person sees what was understood (as chips they
can remove or add to) before the rule is saved, so a misunderstanding is visible instead of silent.

    spec = {
      "products":   ["wordpress", "php"],   software, vendors or technologies (any of them)
      "keywords":   ["hospital"],           other words that must appear (any of them)
      "attacks":    ["rce"],                kinds of attack or flaw (any of them)
      "categories": ["ransomware_leak"],    DarkLens threat types (any of them)
      "cves":       ["CVE-2024-4577"],      a listed CVE alone is enough to match
      "domains":    ["example.com"],        a domain or email alone is enough to match
      "emails":     [],
      "min_severity": "medium",
    }

Matching: every non-empty group must match: (CVEs, domains or emails) and (products or keywords) and attacks and
categories. So "PHP RCE in WordPress" needs WordPress or PHP **and** a code-execution phrase, which keeps general
WordPress news out, and "leaked logins for acme.com" needs acme.com **and** a leak.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

MAX_RULES = 20
MAX_PROMPT = 300
MAX_TERMS = 12
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Kinds of attack or flaw. "words" are what is looked for in the collected text; "asks" are extra phrasings a person
# might type in the prompt that point to the same kind.
ATTACKS: dict[str, dict] = {
    "rce": {"label": "Remote code execution",
            "words": ["remote code execution", "code execution", "rce", "command injection", "command execution", "web shell",
                      "webshell", "shell upload", "arbitrary code", "reverse shell", "code injection", "execute arbitrary"],
            "asks": ["to shell", "get shell", "shell access", "popping shell", "takeover of the server", "run code"]},
    "sqli": {"label": "SQL injection", "words": ["sql injection", "sqli"], "asks": ["sql inject"]},
    "xss": {"label": "Cross-site scripting", "words": ["cross-site scripting", "cross site scripting", "xss"], "asks": []},
    "auth_bypass": {"label": "Login bypass", "words": ["authentication bypass", "auth bypass", "bypass authentication",
                                                       "login bypass", "bypasses authentication"], "asks": ["bypass login"]},
    "privesc": {"label": "Privilege escalation", "words": ["privilege escalation", "privesc", "elevation of privilege",
                                                           "escalate privileges", "root access"], "asks": ["get admin", "get root"]},
    "traversal": {"label": "Path traversal", "words": ["path traversal", "directory traversal"], "asks": []},
    "file_inclusion": {"label": "File inclusion", "words": ["file inclusion", "local file inclusion", "remote file inclusion", "lfi", "rfi"],
                       "asks": []},
    "ssrf": {"label": "Server-side request forgery", "words": ["server-side request forgery", "ssrf"], "asks": []},
    "deserialization": {"label": "Unsafe deserialisation", "words": ["deserialization", "deserialisation"], "asks": []},
    "memory": {"label": "Memory corruption", "words": ["buffer overflow", "heap overflow", "memory corruption", "use-after-free",
                                                       "use after free", "out-of-bounds write"], "asks": []},
    "zeroday": {"label": "Zero-day", "words": ["zero-day", "zero day", "0day", "0-day"], "asks": []},
    "dos": {"label": "Denial of service", "words": ["denial of service", "denial-of-service", "ddos"], "asks": ["take down", "knock offline"]},
    "any_vuln": {"label": "Any flaw or exploit", "words": ["vulnerability", "vulnerabilities", "exploit", "exploited", "flaw", "cve-",
                                                           "security update", "patch", "zero-day", "0day"],
                 "asks": ["vuln", "vulns", "bug", "bugs", "hole", "holes", "weakness", "security issue"]},
}

# DarkLens threat types, and the words in a prompt (and in collected text) that point to them.
CATEGORIES: dict[str, dict] = {
    "ransomware_leak": {"label": "Ransomware", "words": ["ransomware", "extortion", "leak site", "double extortion"]},
    "credential_dump": {"label": "Leaked logins or data", "words": ["data breach", "breach", "breached", "leaked", "credentials",
                                                                    "passwords", "logins", "combolist", "data dump", "stolen data",
                                                                    "data exposed", "exposed data", "account takeover"],
                        "asks": ["leak", "leaks", "login leak", "password leak", "dump", "dumps of"]},
    "phishing_kit": {"label": "Phishing", "words": ["phishing", "phish", "fake login"]},
    "malware_sale": {"label": "Malware", "words": ["malware", "stealer", "infostealer", "trojan", "botnet", "backdoor", "remote access trojan"]},
    "carding_fraud": {"label": "Card fraud", "words": ["carding", "credit card", "card fraud", "cvv", "skimmer", "skimming"]},
    "exploit_sale": {"label": "Exploits for sale", "words": ["exploit for sale", "selling exploit", "exploit sale", "selling a zero-day"]},
    "known_exploited": {"label": "Exploited in the wild", "words": ["actively exploited", "exploited in the wild", "known exploited",
                                                                    "under active attack"], "asks": ["kev", "in the wild"]},
}

# Software, vendors and technologies people commonly ask about. Anything else the person types is kept as a keyword,
# so an unknown product still works; this list only lets the parser label it as software.
PRODUCTS = sorted({
    "wordpress", "woocommerce", "elementor", "drupal", "joomla", "magento", "shopify", "php", "laravel", "symfony", "python",
    "node.js", "nodejs", "npm", "pypi", "java", "log4j", "spring", "struts", "apache", "tomcat", "activemq", "nginx", "iis",
    "microsoft", "windows", "exchange", "sharepoint", "outlook", "office 365", "microsoft 365", "azure", "active directory",
    "citrix", "netscaler", "fortinet", "fortigate", "fortios", "forticlient", "fortimanager", "palo alto", "pan-os",
    "globalprotect", "cisco", "ios xe", "juniper", "sonicwall", "ivanti", "pulse secure", "f5", "big-ip", "vmware", "esxi",
    "vcenter", "oracle", "weblogic", "jenkins", "gitlab", "github", "atlassian", "confluence", "jira", "bitbucket", "openssl",
    "openssh", "linux", "ubuntu", "debian", "red hat", "android", "iphone", "apple", "macos", "chrome", "google", "firefox",
    "mozilla", "adobe", "acrobat", "coldfusion", "sap", "salesforce", "zoom", "slack", "aws", "amazon", "cloudflare", "docker",
    "kubernetes", "redis", "mongodb", "mysql", "postgresql", "elasticsearch", "grafana", "moveit", "screenconnect", "connectwise",
    "teamviewer", "anydesk", "veeam", "zyxel", "d-link", "tp-link", "netgear", "qnap", "synology", "hikvision", "sophos",
    "trend micro", "crowdstrike", "okta", "solarwinds", "kaseya", "zimbra", "roundcube", "telegram", "whatsapp", "samsung",
    "huawei", "mikrotik", "ubiquiti", "check point", "barracuda", "papercut", "nagios", "openai", "chatgpt", "gemini", "ollama",
    "veritas", "commvault", "progress", "telerik", "sitecore", "liferay", "nextcloud", "owncloud", "vbulletin", "phpmyadmin",
}, key=lambda p: -len(p))
ALIASES = {"wp": "wordpress", "o365": "office 365", "m365": "microsoft 365", "k8s": "kubernetes",
           "postgres": "postgresql", "mssql": "microsoft", "fortios": "fortios"}

SEVERITY_ASKS = [
    (r"\bcritical( ones)? only\b|\bonly critical\b|\bjust critical\b|\bcritical\b", "critical"),
    (r"\b(high|serious|urgent|severe|important|major)\b", "high"),
    (r"\bmedium\b", "medium"),
    (r"\b(any severity|every ?thing|all of (it|them)|even minor|even small|low)\b", "low"),
]

STOPWORDS = set("""
a an the and or but if then else of to in on at for from by with without about into over under me my our us we you your i
it its this that these those there here any anything everything something some all every each new latest recent please
alert alerts alerting notify notification notifications tell let know ping warn warning watch monitor track keep eye show
find look looking search when whenever where which who what whose whether is are was were be been being has have had do
does did can could should would will may might must just only also like such as so than too very more most related
regarding around mention mentions mentioned mentioning talk talking talks post posts posted article articles news report
reports reported story stories item items thing things stuff kind type sort level severity get gets got via using use used
attack attacks attacked attacker attackers hack hacks hacked hacker hackers threat threats issue issues problem problems
security cyber online internet web site sites website websites vulnerability vulnerabilities vuln vulns exploit exploits
exploited flaw flaws bug bugs hole holes weakness weaknesses affecting affects affect involving involve target targeting
targets against company companies kit kits tool tools service services sale selling sold offer offers organisation organisations organization organizations
""".split())

_CVE = re.compile(r"\bcve-\d{4}-\d{4,7}\b", re.I)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,24}\b", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|io|co|in|uk|de|fr|ai|app|dev|info|biz|us|ca|au|example|[a-z]{2})\b", re.I)
_WORD = re.compile(r"[a-z0-9][a-z0-9.+#-]*[a-z0-9+#]|[a-z0-9]")


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _has(phrase: str, text: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(phrase.lower())}(?![a-z0-9])", text) is not None


def _take(phrase: str, text: str) -> tuple[bool, str]:
    """Whether the phrase is in the text, and the text with it blanked out (so its words are not reused as keywords)."""
    pat = re.compile(rf"(?<![a-z0-9]){re.escape(phrase.lower())}(?![a-z0-9])")
    if not pat.search(text):
        return False, text
    return True, pat.sub(" ", text)


def empty_spec() -> dict:
    return {"products": [], "keywords": [], "attacks": [], "categories": [], "cves": [], "domains": [], "emails": [],
            "min_severity": "medium"}


def parse_prompt(prompt: str) -> dict:
    """Turn a sentence into a rule spec. Always returns a spec; check `is_empty` before saving it."""
    spec = empty_spec()
    text = _norm(prompt)[:MAX_PROMPT]

    for pat, sev in SEVERITY_ASKS:
        if re.search(pat, text):
            spec["min_severity"] = sev
            break
    # "critical" also names a severity rather than a topic: blank the severity words before looking for topics.
    text = re.sub(r"\b(critical|high|medium|low|serious|urgent|severe|important|major|only|just|ones|even minor|even small)\b", " ", text)

    for m in _CVE.findall(text):
        spec["cves"].append(m.upper())
    text = _CVE.sub(" ", text)
    for m in _EMAIL.findall(text):
        spec["emails"].append(m.lower())
    text = _EMAIL.sub(" ", text)
    for m in _DOMAIN.findall(text):
        if "." in m and not _has(m, " ".join(PRODUCTS)):  # "node.js" is a product, not a domain
            spec["domains"].append(m.lower())
            text = text.replace(m, " ")

    # "php2shell", "wp2rce": a technology joined to what an attacker gets.
    text = re.sub(r"\b([a-z][a-z0-9]{1,20})\s?(?:2|to)\s?(shell|rce|root)\b", r"\1 to shell", text)

    for p in PRODUCTS:
        hit, text = _take(p, text)
        if hit:
            spec["products"].append(p)
    for alias, real in ALIASES.items():
        hit, text = _take(alias.lower(), text)
        if hit and real not in spec["products"]:
            spec["products"].append(real)

    for key, a in ATTACKS.items():
        if key == "any_vuln":
            continue
        for w in a["words"] + a["asks"]:
            hit, text = _take(w, text)
            if hit and key not in spec["attacks"]:
                spec["attacks"].append(key)
    for key, c in CATEGORIES.items():
        for w in c["words"] + c.get("asks", []):
            hit, text = _take(w, text)
            if hit and key not in spec["categories"]:
                spec["categories"].append(key)
    if not spec["attacks"] and any(_has(w, text) for w in ATTACKS["any_vuln"]["words"] + ATTACKS["any_vuln"]["asks"]):
        spec["attacks"].append("any_vuln")
    # an exploited-in-the-wild ask already implies a flaw; no need to also require "vulnerability" words
    if spec["categories"] == ["known_exploited"] and spec["attacks"] == ["any_vuln"]:
        spec["attacks"] = []

    for w in _WORD.findall(text):
        w = w.strip(".-")
        if len(w) < 3 or w.isdigit() or w in STOPWORDS or w in spec["keywords"]:
            continue
        spec["keywords"].append(w)
    spec["keywords"] = spec["keywords"][:5]
    return clean_spec(spec)


def clean_spec(raw) -> dict:
    """Validate a spec that came from a person (the chips can be edited): known keys only, bounded sizes, tidy values."""
    spec = empty_spec()
    if not isinstance(raw, dict):
        return spec

    def strings(key, limit=MAX_TERMS, pattern=None, lower=True):
        vals = raw.get(key) or []
        out = []
        for v in vals if isinstance(vals, list) else []:
            if not isinstance(v, str):
                continue
            v = " ".join(v.split())[:60]
            v = v.lower() if lower else v
            if len(v) < 2 or (pattern and not pattern.fullmatch(v)) or v in out:
                continue
            out.append(v)
        return out[:limit]

    spec["products"] = strings("products", pattern=re.compile(r"[a-z0-9][a-z0-9 .+#_-]*"))
    spec["keywords"] = strings("keywords", pattern=re.compile(r"[a-z0-9][a-z0-9 .+#_-]*"))
    spec["attacks"] = [a for a in strings("attacks") if a in ATTACKS]
    spec["categories"] = [c for c in strings("categories") if c in CATEGORIES]
    spec["cves"] = [c.upper() for c in strings("cves", pattern=re.compile(r"cve-\d{4}-\d{4,7}", re.I), lower=False)]
    spec["domains"] = strings("domains", pattern=re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"))
    spec["emails"] = strings("emails", pattern=re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+"))
    sev = raw.get("min_severity")
    spec["min_severity"] = sev if sev in SEVERITIES else "medium"
    return spec


def is_empty(spec: dict) -> bool:
    return not any(spec.get(k) for k in ("products", "keywords", "attacks", "categories", "cves", "domains", "emails"))


def _labels(spec: dict) -> dict:
    return {
        "attacks": [ATTACKS[a]["label"] for a in spec["attacks"]],
        "categories": [CATEGORIES[c]["label"] for c in spec["categories"]],
    }


def describe(spec: dict) -> str:
    """One plain sentence saying what the rule will catch."""
    parts = []
    l = _labels(spec)
    topics = spec["products"] + spec["keywords"]
    if l["categories"]:
        parts.append(" or ".join(l["categories"]).lower())
    if l["attacks"]:
        parts.append(" or ".join(l["attacks"]).lower())
    what = " involving ".join(parts) if parts else "anything"
    if topics:
        what += " about " + " or ".join(topics)
    direct = spec["cves"] + spec["domains"] + spec["emails"]
    if direct:
        what += (" that also mentions " if parts or topics else " that mentions ") + " or ".join(direct)
    sev = spec["min_severity"]
    floor = "of any severity" if sev == "low" else "rated Critical" if sev == "critical" else f"rated {sev.capitalize()} or worse"
    return f"Alert on {what}, {floor}."


def _any(words: list[str], low: str) -> list[str]:
    return [w for w in words if _has(w, low)]


def match(spec: dict, low_text: str, category: str, severity: str) -> list[str] | None:
    """The evidence (matched words) when the rule matches this text, otherwise None. `low_text` is lower-cased.
    Every non-empty group must match: (CVEs, domains or emails), (products or keywords), attacks, categories."""
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(spec.get("min_severity", "medium"), 1):
        return None
    groups = []
    direct = [c.lower() for c in spec["cves"]] + spec["domains"] + spec["emails"]
    if direct:
        groups.append(_any(direct, low_text))
    if spec["products"] or spec["keywords"]:
        groups.append(_any(spec["products"], low_text) + [k for k in spec["keywords"] if _has_word(k, low_text)])
    if spec["attacks"]:
        groups.append(_any([w for a in spec["attacks"] for w in ATTACKS[a]["words"]], low_text))
    if spec["categories"]:
        hit = [CATEGORIES[c]["label"].lower() for c in spec["categories"] if c == category]
        groups.append(hit or _any([w for c in spec["categories"] for w in CATEGORIES[c]["words"]], low_text))
    if not groups or not all(groups):
        return None
    return sorted({w for g in groups for w in g})


def _stem(word: str) -> str:
    """hospitals -> hospital, banks -> bank: so a keyword matches its singular and plural."""
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 4 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _has_word(word: str, text: str) -> bool:
    stem = _stem(word.lower())
    tail = "(?:ies|y)" if stem.endswith("y") and word.lower().endswith("ies") else "(?:s|es)?"
    if stem.endswith("y") and word.lower().endswith("ies"):
        stem = stem[:-1]
    return re.search(rf"(?<![a-z0-9]){re.escape(stem)}{tail}(?![a-z0-9])", text) is not None


def search_terms(spec: dict) -> list[str]:
    """Words a stored item must contain at least one of to be worth checking against this rule (a cheap first filter
    on the narrowest required group)."""
    direct = [c.lower() for c in spec["cves"]] + spec["domains"] + spec["emails"]
    if direct:
        return sorted(set(direct))
    if spec["products"] or spec["keywords"]:
        return sorted(set(spec["products"] + [_stem(k) for k in spec["keywords"]]))
    if spec["attacks"]:
        return sorted({w for a in spec["attacks"] for w in ATTACKS[a]["words"]})
    return sorted({w for c in spec["categories"] for w in CATEGORIES[c]["words"]})


# ---------------- storage ----------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def view(rule: dict) -> dict:
    spec = rule["spec"]
    return {"id": rule["id"], "prompt": rule["prompt"], "spec": spec, "summary": describe(spec), "labels": _labels(spec),
            "created_at": rule["created_at"]}


def list_rules(con, wid: str) -> list[dict]:
    out = []
    for r in con.execute("SELECT id, prompt, spec, created_at FROM ws_rules WHERE workspace_id=? ORDER BY created_at", (wid,)):
        try:
            spec = clean_spec(json.loads(r["spec"] or "{}"))
        except ValueError:
            continue
        out.append({"id": r["id"], "prompt": r["prompt"], "spec": spec, "created_at": r["created_at"]})
    return out


def add_rule(con, wid: str, prompt: str, spec=None) -> dict | str:
    """The saved rule, or a plain reason it was refused. Without a spec the prompt is parsed here."""
    prompt = " ".join((prompt or "").split())[:MAX_PROMPT]
    spec = clean_spec(spec) if spec is not None else parse_prompt(prompt)
    if is_empty(spec):
        return "That did not name anything to watch for. Try a product, a kind of attack, a CVE or a domain."
    if len(list_rules(con, wid)) >= MAX_RULES:
        return f"A workspace can have at most {MAX_RULES} alert rules. Remove one first."
    rid = "r_" + uuid.uuid4().hex[:12]
    con.execute("INSERT INTO ws_rules (id, workspace_id, prompt, spec, created_at) VALUES (?,?,?,?,?)",
                (rid, wid, prompt or describe(spec), json.dumps(spec), _now()))
    con.commit()
    return {"id": rid, "prompt": prompt or describe(spec), "spec": spec, "created_at": _now()}


def remove_rule(con, wid: str, rid: str) -> None:
    con.execute("DELETE FROM ws_rules WHERE id=? AND workspace_id=?", (rid, wid))
    con.commit()


def vocabulary() -> dict:
    """What the parser knows, for the chip pickers in the website."""
    return {"attacks": {k: v["label"] for k, v in ATTACKS.items()},
            "categories": {k: v["label"] for k, v in CATEGORIES.items()},
            "severities": list(SEVERITIES)}
