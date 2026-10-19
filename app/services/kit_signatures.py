"""Phishing kit signature database and per-kit scoring logic."""
import re
from urllib.parse import urlparse

# Weights: 90+ = near-certain; 40-89 = strong; 1-39 = supporting evidence
PHISHING_KITS: dict[str, dict] = {
    "16Shop": {
        "description": "Prolific PhaaS kit sold on cybercrime forums. Features advanced evasion, bot detection, and support for multiple major brands.",
        "category": "PhaaS",
        "targets": ["Apple", "Amazon", "PayPal", "DHL", "American Express", "Netflix"],
        "threat_actors": ["16Shop operators", "Kit buyers"],
        "first_seen": "2018",
        "signatures": [
            {"type": "html_string", "pattern": "16shop",               "weight": 90},
            {"type": "html_string", "pattern": "16Shop",               "weight": 90},
            {"type": "js_string",   "pattern": "antibot",              "weight": 30},
            {"type": "js_string",   "pattern": "checkBrowser",         "weight": 25},
            {"type": "html_string", "pattern": "Checking your browser","weight": 50},
        ],
    },
    "Zphisher": {
        "description": "Open-source multi-brand phishing toolkit from GitHub, widely used by low-skill attackers.",
        "category": "Open-source toolkit",
        "targets": ["Facebook", "Instagram", "Google", "Netflix", "PayPal", "Snapchat", "Twitter", "GitHub"],
        "threat_actors": ["Various - public distribution"],
        "first_seen": "2019",
        "signatures": [
            {"type": "html_string", "pattern": "zphisher",  "weight": 95},
            {"type": "html_string", "pattern": "Zphisher",  "weight": 95},
            {"type": "js_string",   "pattern": "zphisher",  "weight": 95},
            {"type": "html_string", "pattern": "ZPHISHER",  "weight": 95},
        ],
    },
    "EvilGinx2": {
        "description": "AiTM reverse proxy. Intercepts real authentication flows to bypass 2FA by stealing session cookies.",
        "category": "AiTM Proxy",
        "targets": ["Microsoft 365", "Google Workspace", "GitHub", "Any authenticated service"],
        "threat_actors": ["APT groups", "Ransomware affiliates"],
        "first_seen": "2018",
        "signatures": [
            {"type": "html_string", "pattern": "evilginx",  "weight": 95},
            {"type": "js_string",   "pattern": "phishlet",  "weight": 90},
            {"type": "html_string", "pattern": "ginx",      "weight": 40},
        ],
    },
    "Modlishka": {
        "description": "Automated reverse-proxy phishing framework enabling real-time credential and session token capture.",
        "category": "AiTM Proxy",
        "targets": ["Any web service"],
        "threat_actors": ["Advanced threat actors"],
        "first_seen": "2019",
        "signatures": [
            {"type": "html_string", "pattern": "modlishka", "weight": 95},
            {"type": "js_string",   "pattern": "Modlishka", "weight": 95},
        ],
    },
    "Tycoon 2FA": {
        "description": "AiTM PhaaS sold on Telegram that bypasses Microsoft and Google 2FA by relaying authentication in real time.",
        "category": "AiTM PhaaS",
        "targets": ["Microsoft 365", "Google Workspace"],
        "threat_actors": ["Tycoon Group"],
        "first_seen": "2023",
        "signatures": [
            {"type": "html_string", "pattern": "tycoon2fa",         "weight": 90},
            {"type": "js_regex",    "pattern": r"tycoon.{0,10}2fa", "weight": 85},
            {"type": "js_regex",    "pattern": r"challenge.*turnstile", "weight": 20},
        ],
    },
    "W3LL Panel": {
        "description": "Sophisticated BEC PhaaS targeting Microsoft 365. Features multi-layer anti-bot, fingerprinting, and cookie theft.",
        "category": "BEC PhaaS",
        "targets": ["Microsoft 365", "Business email accounts"],
        "threat_actors": ["W3LL Store operators"],
        "first_seen": "2022",
        "signatures": [
            {"type": "html_string", "pattern": "w3ll",           "weight": 90},
            {"type": "js_string",   "pattern": "W3LL",           "weight": 90},
            {"type": "js_string",   "pattern": "antibot_check",  "weight": 35},
            {"type": "js_string",   "pattern": "finger_print",   "weight": 30},
        ],
    },
    "PerSwaysion": {
        "description": "BEC kit mimicking Microsoft SharePoint / OneDrive file-share notifications to steal Office 365 credentials.",
        "category": "BEC Phishing",
        "targets": ["Microsoft 365", "OneDrive", "SharePoint"],
        "threat_actors": ["TA2552"],
        "first_seen": "2019",
        "signatures": [
            {"type": "html_string", "pattern": "perswaysion",                    "weight": 95},
            {"type": "html_regex",  "pattern": r"sharepoint\.live|onedrive\.live", "weight": 20},
        ],
    },
    "Darcula": {
        "description": "Modern PhaaS using React PWA templates primarily for SMS phishing (smishing) campaigns.",
        "category": "PhaaS (Smishing)",
        "targets": ["Royal Mail", "USPS", "FedEx", "Banks", "Telecom"],
        "threat_actors": ["Darcula / Magic Cat operators"],
        "first_seen": "2024",
        "signatures": [
            {"type": "html_string", "pattern": "darcula", "weight": 95},
            {"type": "js_string",   "pattern": "darcula", "weight": 95},
        ],
    },
    "Robin Banks": {
        "description": "PhaaS platform offering customizable pages for US/UK financial institutions via subscription.",
        "category": "PhaaS",
        "targets": ["Citibank", "Bank of America", "Capital One", "Wells Fargo", "USAA", "Rogers"],
        "threat_actors": ["Robin Banks operators"],
        "first_seen": "2022",
        "signatures": [
            {"type": "html_string", "pattern": "robinbanks",  "weight": 95},
            {"type": "js_string",   "pattern": "robin_banks", "weight": 90},
        ],
    },
    "Kr3pto": {
        "description": "UK-focused banking phishing kit with real-time OTP interception targeting major UK high-street banks.",
        "category": "Banking Phishing",
        "targets": ["HSBC", "Lloyds Bank", "NatWest", "Halifax", "Nationwide", "Barclays"],
        "threat_actors": ["TA2535", "UK cybercriminal groups"],
        "first_seen": "2020",
        "signatures": [
            {"type": "html_string", "pattern": "kr3pto",                          "weight": 95},
            {"type": "html_string", "pattern": "Kr3pto",                          "weight": 95},
            {"type": "js_string",   "pattern": "memorableWord",                   "weight": 45},
            {"type": "html_regex",  "pattern": r"memorable[\s\-_]?word",          "weight": 40},
        ],
    },
    "Caffeine": {
        "description": "Open-access PhaaS platform with no buyer vetting, providing Microsoft and Google credential-theft templates.",
        "category": "PhaaS",
        "targets": ["Microsoft 365", "Google Workspace"],
        "threat_actors": ["Caffeine platform buyers"],
        "first_seen": "2022",
        "signatures": [
            {"type": "js_string",   "pattern": "caffeine_kit",  "weight": 90},
            {"type": "html_string", "pattern": "caffeine-kit",  "weight": 90},
        ],
    },
    "Muraena": {
        "description": "Go-based AiTM reverse proxy phishing framework with automated session token capture.",
        "category": "AiTM Proxy",
        "targets": ["Any web service"],
        "threat_actors": ["Red teamers", "Advanced threat actors"],
        "first_seen": "2019",
        "signatures": [
            {"type": "html_string", "pattern": "muraena", "weight": 95},
        ],
    },
    "DarkPhish": {
        "description": "Telegram-distributed phishing kit builder targeting crypto exchanges and wallet services.",
        "category": "Crypto Phishing",
        "targets": ["Binance", "Coinbase", "MetaMask", "Ledger", "Trezor", "Trust Wallet"],
        "threat_actors": ["Crypto theft groups"],
        "first_seen": "2021",
        "signatures": [
            {"type": "html_string", "pattern": "darkphish",                                                     "weight": 95},
            {"type": "html_regex",  "pattern": r"(seed.?phrase|recovery.?phrase|secret.?phrase|private.?key)",  "weight": 70},
            {"type": "js_regex",    "pattern": r"(metamask|ledger|trezor|trustwallet)",                         "weight": 25},
        ],
    },
    "PhishNow (BitB)": {
        "description": "Browser-in-the-browser attack framework rendering fake OAuth popups indistinguishable from real browser windows.",
        "category": "BitB / Popup Phishing",
        "targets": ["Google", "Microsoft", "Apple", "Facebook (SSO)"],
        "threat_actors": ["Various"],
        "first_seen": "2022",
        "signatures": [
            {"type": "html_regex", "pattern": r"browser.?in.?the.?browser",           "weight": 90},
            {"type": "html_regex", "pattern": r"(fakepopup|fake_popup|popup_window.*oauth)", "weight": 70},
            {"type": "js_regex",   "pattern": r"bitb|fake.{0,5}browser",              "weight": 80},
        ],
    },
}


def score_kit(kit: dict, html_lower: str, js_body: str, url: str) -> int:
    """Return the total signature-match weight for one kit (0 if nothing matched)."""
    path  = urlparse(url).path
    total = 0
    for sig in kit.get("signatures", []):
        pat, w, t = sig["pattern"], sig["weight"], sig["type"]
        try:
            matched = False
            if t == "html_string":
                matched = pat.lower() in html_lower
            elif t == "html_regex":
                matched = bool(re.search(pat, html_lower, re.I))
            elif t == "js_string":
                matched = pat.lower() in js_body.lower()
            elif t == "js_regex":
                matched = bool(re.search(pat, js_body, re.I))
            elif t == "url_regex":
                matched = bool(re.search(pat, url, re.I))
            elif t == "path_regex":
                matched = bool(re.search(pat, path, re.I))
            if matched:
                total += w
        except re.error:
            pass
    return total
