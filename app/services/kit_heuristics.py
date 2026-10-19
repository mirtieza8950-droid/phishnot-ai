"""Kit-agnostic heuristic detectors for phishing page analysis."""
import re
from urllib.parse import urlparse

_RE_CARD     = re.compile(r"(card.?number|cardnum|ccnum|cc_num|credit.?card|card.?no|cvv|cvc|expir|exp_date|exp.?month|exp.?year)", re.I)
_RE_OTP      = re.compile(r"(otp|one.?time|verification.?code|sms.?code|auth.?code|mfa.?code|totp|tac\b)", re.I)
_RE_PASS     = re.compile(r"(password|passwd|pass\b|pwd|secret\b|pin\b)", re.I)
_RE_EMAIL    = re.compile(r"(email|e.?mail|username|user.?name|login\b|userid)", re.I)
_RE_SEED     = re.compile(r"(seed.?phrase|mnemonic|recovery.?phrase|secret.?phrase|private.?key)", re.I)
_RE_TELEGRAM = re.compile(r"api\.telegram\.org", re.I)
_RE_DISCORD  = re.compile(r"discord(app)?\.com/api/webhooks", re.I)
_RE_PHPMAIL  = re.compile(r"(mail\s*\(\s*['\"]|sendmail\b|phpmailer|SwiftMailer)", re.I)
_RE_GATE     = re.compile(r"\b(log|collect|submit|gate|result|save|data|post)\.php\b", re.I)
_RE_OBFUSC   = re.compile(r"(eval\s*\(|String\.fromCharCode|unescape\s*\(|atob\s*\(|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")
_RE_ANTIBOT  = re.compile(r"(navigator\.webdriver|phantomjs|selenium|headless|puppeteer|playwright|crawl|bot.?detect)", re.I)
_RE_REDIRECT = re.compile(r"(window\.location\s*=.*?google|document\.location\s*=.*?google)", re.I)
_RE_IPCHECK  = re.compile(r"(ipify\.org|ip-api\.com|ipinfo\.io|checkip\.amazonaws|whatismyip)", re.I)
_RE_BRANDS   = re.compile(
    r"\b(paypal|amazon|apple|microsoft|google|facebook|instagram|netflix|coinbase|"
    r"binance|metamask|chase|wellsfargo|barclays|hsbc|natwest|lloyds|halifax|"
    r"dhl|fedex|usps|ups|royal.?mail|citibank|bankofamerica|capitalonebank|"
    r"americanexpress|dropbox|linkedin|docusign|adobe|ledger|trezor)\b",
    re.I,
)
_RE_IP_HOST  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _attr(inp: dict) -> str:
    return " ".join(filter(None, [inp.get("name", ""), inp.get("id", ""),
                                   inp.get("placeholder", ""), inp.get("type", "")]))


def build_indicators(
    html: str,
    html_lower: str,
    js_body: str,
    inputs: list[dict],
    url: str,
    final_url: str,
) -> list[dict]:
    """Return the list of heuristic indicator dicts for a fetched page."""
    pw_inputs   = [i for i in inputs if _RE_PASS.search(_attr(i))]
    em_inputs   = [i for i in inputs if _RE_EMAIL.search(_attr(i))]
    card_inputs = [i for i in inputs if _RE_CARD.search(_attr(i))]
    otp_inputs  = [i for i in inputs if _RE_OTP.search(_attr(i))]
    seed_inputs = [i for i in inputs if _RE_SEED.search(_attr(i))]

    out: list[dict] = []

    if pw_inputs:
        out.append({
            "type": "credential_form", "severity": "high",
            "title": "Password Capture Form",
            "detail": f"{len(pw_inputs)} password field(s): {[i.get('name') or i.get('id', '?') for i in pw_inputs[:3]]}",
        })
    if em_inputs and pw_inputs:
        out.append({
            "type": "credential_harvesting", "severity": "high",
            "title": "Login Credential Harvesting",
            "detail": "Email/username + password fields present - classic credential phishing form.",
        })
    if card_inputs:
        out.append({
            "type": "credit_card", "severity": "critical",
            "title": "Credit Card Capture Form",
            "detail": f"Payment fields: {[i.get('name') or i.get('id', '?') for i in card_inputs[:5]]}",
        })
    if otp_inputs:
        out.append({
            "type": "otp_bypass", "severity": "critical",
            "title": "OTP / 2FA Bypass Form",
            "detail": "One-time-code input detected - attacker likely relaying credentials in real time.",
        })
    if seed_inputs or _RE_SEED.search(html[:80_000]):
        out.append({
            "type": "crypto_seed", "severity": "critical",
            "title": "Crypto Seed Phrase Capture",
            "detail": "Page asks for wallet recovery/seed phrase - targets cryptocurrency theft.",
        })

    if _RE_TELEGRAM.search(html):
        out.append({
            "type": "exfil_telegram", "severity": "critical",
            "title": "Telegram Bot Exfiltration",
            "detail": "api.telegram.org referenced - stolen credentials likely forwarded to a Telegram bot.",
        })
    if _RE_DISCORD.search(html):
        out.append({
            "type": "exfil_discord", "severity": "critical",
            "title": "Discord Webhook Exfiltration",
            "detail": "Discord webhook URL found - data exfiltrated to an attacker-controlled Discord channel.",
        })
    if _RE_PHPMAIL.search(js_body) or _RE_GATE.search(html):
        out.append({
            "type": "exfil_email", "severity": "high",
            "title": "PHP Mail / Gate Script Exfiltration",
            "detail": "PHP mailer or gate/submit/collect.php artifacts found - credentials sent by email.",
        })

    if _RE_ANTIBOT.search(js_body):
        out.append({
            "type": "antibot", "severity": "medium",
            "title": "Anti-Bot / Anti-Analysis",
            "detail": "Headless browser / crawler detection - designed to evade automated security scanners.",
        })
    if _RE_REDIRECT.search(js_body):
        out.append({
            "type": "bot_redirect", "severity": "medium",
            "title": "Bot Redirect to Legitimate Site",
            "detail": "Script redirects suspected crawlers to Google/legitimate site to avoid detection.",
        })
    if _RE_OBFUSC.search(js_body):
        out.append({
            "type": "obfuscation", "severity": "medium",
            "title": "JavaScript Obfuscation",
            "detail": "eval(), String.fromCharCode(), atob(), or hex/unicode escapes detected.",
        })
    if _RE_IPCHECK.search(html):
        out.append({
            "type": "ip_collection", "severity": "medium",
            "title": "Victim IP / Geo Collection",
            "detail": "Third-party IP-lookup service referenced - attacker likely geo-filtering victims.",
        })

    brands = list({b.lower() for b in _RE_BRANDS.findall(html[:80_000])})
    if brands:
        out.append({
            "type": "brand_spoofing", "severity": "high",
            "title": "Brand Impersonation",
            "detail": f"References to: {', '.join(sorted(brands)[:7])}",
        })

    gate_files = _RE_GATE.findall(html)
    if gate_files:
        out.append({
            "type": "kit_artifacts", "severity": "high",
            "title": "Phishing Kit Artifact Scripts",
            "detail": f"Data-collection scripts: {', '.join(set(gate_files[:5]))}",
        })

    orig_host  = urlparse(url).hostname or ""
    final_host = urlparse(final_url).hostname or ""
    if orig_host and final_host and orig_host != final_host:
        out.append({
            "type": "redirect", "severity": "medium",
            "title": "Domain Redirect",
            "detail": f"{orig_host} -> {final_host}",
        })
    if final_host and _RE_IP_HOST.match(final_host):
        out.append({
            "type": "ip_hosted", "severity": "high",
            "title": "Hosted on Raw IP Address",
            "detail": f"Served from {final_host} - common for disposable phishing infrastructure.",
        })

    return out


def compute_risk_score(indicators: list[dict], kit_confidence: int, has_password: bool, matched: bool) -> int:
    sev = {"critical": 3, "high": 2, "medium": 1}
    ind_score  = sum(sev.get(i["severity"], 0) for i in indicators)
    kit_boost  = 3 if kit_confidence >= 80 else 2 if kit_confidence >= 40 else 1 if matched else 0
    return min(10, round(ind_score * 0.45 + kit_boost + (1 if has_password else 0)))
