"""Category -> MITRE ATT&CK technique mapping, so each alert says what attacker behaviour it points to."""

TECHNIQUES = {
    "ransomware_leak": [("T1486", "Data Encrypted for Impact"), ("T1567", "Exfiltration Over Web Service")],
    "credential_dump": [("T1078", "Valid Accounts"), ("T1589.001", "Gather Victim Identity Information: Credentials")],
    "exploit_sale": [("T1190", "Exploit Public-Facing Application"), ("T1133", "External Remote Services")],
    "phishing_kit": [("T1566", "Phishing"), ("T1111", "Multi-Factor Authentication Interception")],
    "malware_sale": [("T1588.001", "Obtain Capabilities: Malware"), ("T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "carding_fraud": [("T1657", "Financial Theft")],
    "known_exploited": [("T1190", "Exploit Public-Facing Application")],
    "threat_chatter": [("T1498", "Network Denial of Service"), ("T1491", "Defacement")],
}


def techniques(category: str) -> list[dict]:
    return [{"id": i, "name": n, "url": f"https://attack.mitre.org/techniques/{i.replace('.', '/')}/"}
            for i, n in TECHNIQUES.get(category, [])]
