"""
Mobile Phishing Detection Engine - pure static analysis.

Three analysis surfaces:
  1. SMS / Smishing  - brand impersonation, urgency, OTP theft, URL shorteners
  2. Deep Link Abuse - intent://, javascript:, market://, fake custom schemes
  3. Mobile URL      - smishing landing-page patterns, short-link fingerprints
"""

import re
from urllib.parse import urlparse, unquote

# ── URL extraction ──────────────────────────────────────────────────────────────

_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+', re.I)

_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'is.gd',
    'buff.ly', 'cutt.ly', 'short.io', 'rb.gy', 'shorturl.at', 'v.gd',
    'tiny.cc', 'lnkd.in', 'dlvr.it', 'ift.tt', 'smarturl.it',
    'bl.ink', 'bitly.com', 'soo.gd', 'clck.ru', 'x.co', 'su.pr',
}

# ── Brand databases ─────────────────────────────────────────────────────────────

_DELIVERY_BRANDS: dict[str, str] = {
    'usps': 'USPS', 'fedex': 'FedEx', 'dhl': 'DHL', 'ups': 'UPS',
    'royal mail': 'Royal Mail', 'royalmail': 'Royal Mail',
    'amazon': 'Amazon', 'evri': 'Evri', 'hermes': 'Hermes',
    'parcelforce': 'Parcelforce', 'yodel': 'Yodel', 'dpd': 'DPD',
    'gls': 'GLS', 'postnl': 'PostNL', 'australia post': 'Australia Post',
    'la poste': 'La Poste', 'correos': 'Correos',
}

_FINANCIAL_BRANDS: dict[str, str] = {
    'paypal': 'PayPal', 'venmo': 'Venmo', 'cashapp': 'Cash App',
    'zelle': 'Zelle', 'wise': 'Wise', 'revolut': 'Revolut',
    'chase': 'Chase', 'wells fargo': 'Wells Fargo', 'wellsfargo': 'Wells Fargo',
    'bank of america': 'Bank of America', 'citi': 'Citibank',
    'hsbc': 'HSBC', 'lloyds': 'Lloyds', 'barclays': 'Barclays',
    'natwest': 'NatWest', 'halifax': 'Halifax', 'santander': 'Santander',
    'coinbase': 'Coinbase', 'binance': 'Binance', 'blockchain': 'Blockchain.com',
    'american express': 'Amex', 'amex': 'Amex', 'capital one': 'Capital One',
    'discover': 'Discover', 'td bank': 'TD Bank', 'cibc': 'CIBC',
    'rbc': 'RBC', 'bmo': 'BMO', 'scotiabank': 'Scotiabank',
}

_CARRIER_BRANDS: dict[str, str] = {
    'at&t': 'AT&T', 'att': 'AT&T', 'verizon': 'Verizon', 'tmobile': 'T-Mobile',
    't-mobile': 'T-Mobile', 'sprint': 'Sprint', 'o2': 'O2',
    'vodafone': 'Vodafone', 'ee': 'EE', 'three': 'Three', 'bt': 'BT',
    'sky': 'Sky', 'rogers': 'Rogers', 'bell': 'Bell', 'telus': 'Telus',
    'optus': 'Optus', 'telstra': 'Telstra', 'mint mobile': 'Mint Mobile',
    'cricket': 'Cricket', 'metro': 'Metro by T-Mobile', 'boost': 'Boost Mobile',
    'straight talk': 'Straight Talk', 'xfinity': 'Xfinity Mobile',
}

_GOVT_BRANDS: dict[str, str] = {
    'irs': 'IRS', 'hmrc': 'HMRC', 'social security': 'SSA', 'ssa': 'SSA',
    'medicare': 'Medicare', 'medicaid': 'Medicaid', 'customs': 'Customs',
    'dmv': 'DMV', 'dvla': 'DVLA', 'gov.uk': 'UK Government',
    'fbi': 'FBI', 'dea': 'DEA', 'border patrol': 'Border Patrol',
    'unemployment': 'Unemployment Office', 'benefits': 'Benefits Agency',
}

_ALL_BRANDS = {**_DELIVERY_BRANDS, **_FINANCIAL_BRANDS, **_CARRIER_BRANDS, **_GOVT_BRANDS}

# ── SMS pattern regexes ─────────────────────────────────────────────────────────

_URGENCY = re.compile(
    r'\b(urgent|immediately|act now|expires?|last chance|final notice|'
    r'within \d+ hours?|today only|deadline|respond now|action required|'
    r'limited time|do not ignore|your account will be|suspended|blocked|'
    r'verify now|confirm now|update now)\b',
    re.I,
)
_OTP_THEFT = re.compile(
    r'\b(one.?time|otp|verification code|auth.?code|security code|pin)\b.{0,60}'
    r'\b(enter|type|provide|share|reply|send|confirm|forward)\b'
    r'|\b(reply|send|forward).{0,30}\b(code|otp|pin)\b',
    re.I,
)
_PRIZE = re.compile(
    r'\b(congratulations?|you.ve won|you are (a |the )?winner|'
    r'selected|eligible for|claim your (prize|reward|gift|voucher|bonus)|'
    r'free (iphone|gift card|prize|reward)|lottery|lucky draw)\b',
    re.I,
)
_DELIVERY_ACTION = re.compile(
    r'\b(your package|your parcel|delivery|shipment|tracking|'
    r'customs fee|re-?delivery|update (delivery|address)|'
    r'could not be delivered|on hold|awaiting collection|'
    r'pay (to|the|a) (fee|charge|duty)|postage due)\b',
    re.I,
)
_ACCOUNT_ACTION = re.compile(
    r'\b(unusual activity|suspicious (activity|login|sign.?in)|'
    r'account (suspended|locked|compromised|breached|at risk)|'
    r'unauthorized (access|transaction)|verify your identity|'
    r'confirm your (details|account|payment|transaction)|'
    r'security alert|fraud alert)\b',
    re.I,
)
_PHONE_RE = re.compile(r'\+?[\d\s\-\(\)]{10,15}')

# ── Deep link patterns ──────────────────────────────────────────────────────────

_SAFE_SCHEMES = {
    'http', 'https', 'tel', 'sms', 'mailto', 'facetime', 'maps',
    'comgooglemaps', 'fb', 'twitter', 'tg', 'whatsapp', 'line',
    'spotify', 'netflix', 'youtube', 'instagram', 'snapchat',
}
_CRITICAL_SCHEMES = {'javascript', 'data', 'vbscript', 'file', 'blob'}
_SUSPICIOUS_SCHEMES = {'intent', 'market', 'content', 'android-app'}

# Regex for Android intent URL anatomy
_INTENT_RE = re.compile(
    r'intent://(?P<host>[^#?]*)(?:#Intent;)?(?P<extras>[^;]*(?:;[^;]*)*)?;?end',
    re.I,
)
_INTENT_PACKAGE = re.compile(r'package=([a-zA-Z0-9._]+)')
_INTENT_ACTION  = re.compile(r'action=([^\s;]+)')
_INTENT_SCHEME  = re.compile(r'scheme=([^\s;]+)')

_KNOWN_APP_SCHEMES: dict[str, str] = {
    'fb': 'Facebook', 'fbmessenger': 'Messenger', 'fb-messenger': 'Messenger',
    'twitter': 'Twitter/X', 'instagram': 'Instagram', 'snapchat': 'Snapchat',
    'tg': 'Telegram', 'whatsapp': 'WhatsApp', 'viber': 'Viber',
    'line': 'LINE', 'discord': 'Discord', 'signal': 'Signal',
    'spotify': 'Spotify', 'netflix': 'Netflix', 'youtube': 'YouTube',
    'googlechrome': 'Chrome', 'googlegmail': 'Gmail', 'googlemaps': 'Maps',
    'googlephotos': 'Photos', 'googledrive': 'Drive', 'slack': 'Slack',
    'zoom': 'Zoom', 'teams': 'Microsoft Teams', 'outlook': 'Outlook',
    'onedrive': 'OneDrive', 'dropbox': 'Dropbox', 'paypal': 'PayPal',
    'venmo': 'Venmo', 'cashapp': 'Cash App', 'coinbase': 'Coinbase',
}

_TYPO_SCHEMES = re.compile(
    r'^(g[o0]{2}g[l1]e|faceb[o0]{2}k|app[l1]e|microso[f1]t|paypa[l1]|amaz[o0]n)',
    re.I,
)

# ── Mobile URL patterns ────────────────────────────────────────────────────────

_MOBILE_SUSPICIOUS_KEYWORDS = re.compile(
    r'(verify|secure|account|update|login|signin|auth|confirm|'
    r'validate|recover|unlock|suspend|alert|notice|package|parcel|'
    r'tracking|delivery|refund|reward|prize|offer|win|claim)',
    re.I,
)
_SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.work', '.buzz', '.link', '.click', '.zip', '.mov', '.shop',
    '.online', '.site', '.website', '.pw', '.cc',
}
_MOBILE_PATH_RE = re.compile(r'/(sms|msg|m|mobile|app|go|l|r|c)/[A-Za-z0-9_-]{3,}', re.I)


# ── Scoring helpers ─────────────────────────────────────────────────────────────

def _risk_10(raw: int) -> int:
    return min(10, round(raw / 10))


def _detect_brand(text_lower: str) -> tuple[str | None, str]:
    """Return (brand_key, brand_name) for the highest-priority matched brand."""
    for key, name in _ALL_BRANDS.items():
        if key in text_lower:
            return key, name
    return None, ""


def _extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,)>\"'") for u in _URL_RE.findall(text)]


def _is_shortener(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower().lstrip("www.")
    return host in _SHORTENERS


# ── 1. SMS / Smishing analysis ──────────────────────────────────────────────────

def analyze_sms(text: str) -> dict:
    text_lower = text.lower()
    findings: list[dict] = []
    score = 0
    indicators: dict = {}

    urls = _extract_urls(text)
    indicators["urls_found"] = len(urls)

    # Brand impersonation
    brand_key, brand_name = _detect_brand(text_lower)
    indicators["impersonated_brand"] = brand_name or None
    if brand_name:
        # Delivery brand + action = very suspicious
        if brand_key in _DELIVERY_BRANDS and _DELIVERY_ACTION.search(text):
            score += 45
            findings.append({
                "severity": "critical",
                "title": f"{brand_name} Delivery Scam",
                "detail": f"Message impersonates {brand_name} with a delivery-related action request - "
                          "the most common smishing template globally.",
            })
        elif brand_key in _FINANCIAL_BRANDS:
            score += 40
            findings.append({
                "severity": "critical",
                "title": f"{brand_name} Financial Impersonation",
                "detail": f"Message impersonates {brand_name}. Legitimate financial institutions "
                          "never request credentials or payments via SMS.",
            })
        elif brand_key in _CARRIER_BRANDS:
            score += 30
            findings.append({
                "severity": "high",
                "title": f"{brand_name} Carrier Impersonation",
                "detail": f"Message impersonates {brand_name}. Carriers never ask customers to "
                          "click links to resolve billing or data issues.",
            })
        elif brand_key in _GOVT_BRANDS:
            score += 40
            findings.append({
                "severity": "critical",
                "title": f"{brand_name} Government Impersonation",
                "detail": f"Message claims to be from {brand_name}. Government agencies communicate "
                          "by post, not unsolicited SMS.",
            })

    # OTP / verification code theft
    if _OTP_THEFT.search(text):
        score += 50
        indicators["otp_theft_attempt"] = True
        findings.append({
            "severity": "critical",
            "title": "OTP / Verification Code Theft",
            "detail": "Message asks the recipient to share, enter, or forward a one-time code. "
                      "This is the hallmark of a real-time phishing relay attack.",
        })
    else:
        indicators["otp_theft_attempt"] = False

    # Prize / lottery scam
    if _PRIZE.search(text):
        score += 35
        indicators["prize_scam"] = True
        findings.append({
            "severity": "high",
            "title": "Prize / Lottery Scam",
            "detail": "Message claims the recipient has won something. Unsolicited prize notifications "
                      "via SMS are universally fraudulent.",
        })
    else:
        indicators["prize_scam"] = False

    # Urgency language
    urgency_hits = _URGENCY.findall(text)
    if urgency_hits:
        score += 20
        indicators["urgency_language"] = True
        findings.append({
            "severity": "high",
            "title": f"Urgency / Pressure Language ({len(urgency_hits)} phrase(s))",
            "detail": f"Phrases: {', '.join(set(h.lower() for h in urgency_hits[:4]))}. "
                      "Artificial urgency is a core social-engineering technique in smishing.",
        })
    else:
        indicators["urgency_language"] = False

    # Account-action language (without brand already caught above)
    if _ACCOUNT_ACTION.search(text) and not brand_key:
        score += 25
        findings.append({
            "severity": "high",
            "title": "Account Suspension / Security Alert Language",
            "detail": "Message claims the recipient's account has a security problem requiring immediate action.",
        })

    # URL shorteners
    shortener_urls = [u for u in urls if _is_shortener(u)]
    if shortener_urls:
        score += 30
        indicators["has_url_shortener"] = True
        findings.append({
            "severity": "high",
            "title": f"URL Shortener(s) in SMS ({len(shortener_urls)})",
            "detail": f"Links: {', '.join(shortener_urls[:3])}. "
                      "URL shorteners in SMS hide the true destination - a defining smishing technique.",
        })
    else:
        indicators["has_url_shortener"] = False

    # Raw suspicious URLs (not shorteners)
    for url in urls:
        if not _is_shortener(url):
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            sus_kw = _MOBILE_SUSPICIOUS_KEYWORDS.search(host + parsed.path)
            if sus_kw or any(host.endswith(tld) for tld in _SUSPICIOUS_TLDS):
                score += 20
                indicators["has_suspicious_url"] = True
                findings.append({
                    "severity": "high",
                    "title": "Suspicious URL in SMS",
                    "detail": f"URL contains phishing keywords or a high-risk TLD: {url[:80]}",
                })
                break

    # No links at all in a suspicious message = low risk
    if not urls and score < 20:
        score = max(score, 5)

    threat_type = _sms_threat_type(findings)
    return {
        "text_preview": text[:160],
        "risk_score": _risk_10(score),
        "threat_type": threat_type,
        "indicators": indicators,
        "urls_found": urls,
        "url_count": len(urls),
        "findings": findings,
        "recommendations": _sms_recommendations(findings, brand_name),
    }


def _sms_threat_type(findings: list[dict]) -> str | None:
    titles = " ".join(f["title"] for f in findings).lower()
    if "otp" in titles:             return "Real-Time OTP Relay Attack"
    if "delivery" in titles:        return "Package Delivery Scam (Smishing)"
    if "financial" in titles:       return "Financial Institution Smishing"
    if "government" in titles:      return "Government Impersonation Smishing"
    if "prize" in titles:           return "Prize / Lottery Scam"
    if "carrier" in titles:         return "Mobile Carrier Smishing"
    if "account suspension" in titles: return "Account Takeover Smishing"
    if findings:                    return "Smishing"
    return None


def _sms_recommendations(findings: list[dict], brand: str) -> list[str]:
    recs = []
    titles = " ".join(f["title"] for f in findings).lower()
    if "otp" in titles:
        recs.append("Never share verification codes with anyone - your bank, carrier, or any company will never ask for them over SMS.")
    if brand:
        recs.append(f"Contact {brand} directly through their official website or app - never through a link in an SMS.")
    if "shortener" in titles:
        recs.append("Avoid clicking shortened URLs in SMS messages. Use a URL expander service to preview the destination first.")
    if "prize" in titles:
        recs.append("Unsolicited prize notifications are always scams. Delete the message.")
    if "delivery" in titles:
        recs.append("Track packages only through the carrier's official website or app using your order confirmation number.")
    if not recs:
        recs.append("If in doubt, do not click any links in the message. Contact the sender through official channels only.")
    return recs


# ── 2. Deep Link analysis ───────────────────────────────────────────────────────

def analyze_deeplink(link: str) -> dict:
    link = link.strip()
    link_decoded = unquote(link)
    findings: list[dict] = []
    score = 0

    # Determine scheme
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/', link)
    if not scheme_match:
        # Try without //
        scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):/', link)
    scheme = scheme_match.group(1).lower() if scheme_match else "unknown"

    parsed      = urlparse(link)
    host        = (parsed.hostname or "").lower()
    threat_type = None

    # Critical schemes
    if scheme in _CRITICAL_SCHEMES:
        score += 80
        threat_type = f"{scheme.title()}: Code Injection"
        findings.append({
            "severity": "critical",
            "title": f"Dangerous URI Scheme - `{scheme}:`",
            "detail": (
                f"The `{scheme}:` scheme can execute code or access local files directly. "
                "Used in deep-link injection attacks to bypass browser security."
            ),
        })

    # Android intent:// abuse
    elif scheme == "intent":
        score += 40
        intent_pkg = _INTENT_PACKAGE.search(link)
        intent_action = _INTENT_ACTION.search(link)
        intent_scheme  = _INTENT_SCHEME.search(link)
        pkg  = intent_pkg.group(1)  if intent_pkg   else None
        act  = intent_action.group(1) if intent_action else None
        sch  = intent_scheme.group(1)  if intent_scheme  else None

        threat_type = "Android Intent Scheme Abuse"
        findings.append({
            "severity": "high",
            "title": "Android `intent://` Deep Link",
            "detail": (
                f"Package: {pkg or 'unspecified'}  |  Action: {act or 'unspecified'}  |  "
                f"Fallback scheme: {sch or 'none'}. "
                "Intent URLs can open arbitrary apps, trigger installs, or pass malicious extras."
            ),
        })

        # Intent pointing to browser with JavaScript
        if sch in ('javascript', 'data') or (act and 'VIEW' in act.upper() and sch in ('javascript', 'data')):
            score += 40
            findings.append({
                "severity": "critical",
                "title": "Intent Scheme Escalating to JavaScript Execution",
                "detail": f"intent:// with scheme={sch} can execute arbitrary JavaScript in the target app's WebView.",
            })

        # Suspicious/fake package name
        if pkg and re.search(r'(phish|hack|steal|evil|fake|malware)', pkg, re.I):
            score += 30
            findings.append({
                "severity": "critical",
                "title": f"Suspicious Package Name: `{pkg}`",
                "detail": "Package name contains keywords associated with malicious Android apps.",
            })

    # Play Store force-install
    elif scheme == "market":
        score += 45
        threat_type = "Forced App Install via market://"
        findings.append({
            "severity": "critical",
            "title": "Play Store Force-Install (`market://`)",
            "detail": f"Link attempts to trigger a Google Play install prompt: {link[:100]}. "
                      "Used to distribute malicious apps without user context.",
        })

    # Custom scheme - check for impersonation
    elif scheme not in _SAFE_SCHEMES:
        legitimate_app = _KNOWN_APP_SCHEMES.get(scheme)
        if legitimate_app:
            score += 10  # legitimate custom scheme
        elif _TYPO_SCHEMES.match(scheme):
            score += 55
            threat_type = "Deep-Link App Impersonation"
            findings.append({
                "severity": "critical",
                "title": f"Typosquatted App Scheme: `{scheme}://`",
                "detail": f"Scheme resembles a known app's URI scheme but contains character substitutions. "
                          "May hijack authentication flows or redirect to malicious pages.",
            })
        else:
            score += 15
            findings.append({
                "severity": "medium",
                "title": f"Unknown Custom URI Scheme: `{scheme}://`",
                "detail": f"Unrecognised scheme `{scheme}`. Verify this links to a trusted app before opening.",
            })

    # HTTPS/HTTP with suspicious characteristics
    elif scheme in ('http', 'https'):
        if scheme == 'http':
            score += 15
            findings.append({"severity": "medium", "title": "HTTP Deep Link (Not Encrypted)",
                              "detail": "Universal links and app links should always use HTTPS."})
        # Open redirect patterns
        if re.search(r'(?:redirect|url|link|goto|return|next|dest)=https?://', link, re.I):
            score += 25
            findings.append({"severity": "high", "title": "Open Redirect in Deep Link",
                              "detail": "Deep link contains a redirect parameter pointing to an external URL."})
        # App association bypass
        if re.search(r'\.well-known/apple-app-site-association|assetlinks\.json', link, re.I):
            findings.append({"severity": "low", "title": "Universal Link / App Association File Reference",
                              "detail": "References app-link configuration files. Verify the domain is legitimate."})

    # AiTM / token theft in query params
    for param in ('access_token', 'id_token', 'refresh_token', 'code'):
        if f'{param}=' in link_decoded:
            score += 45
            findings.append({
                "severity": "critical",
                "title": f"OAuth Token in Deep Link - `{param}`",
                "detail": f"The `{param}` parameter is present in this deep link. "
                          "Tokens in deep links can be intercepted by malicious apps registered for the same scheme.",
            })

    if not threat_type and findings:
        threat_type = "Suspicious Deep Link"

    return {
        "link": link,
        "scheme": scheme,
        "risk_score": _risk_10(score),
        "threat_type": threat_type,
        "findings": findings,
        "recommendations": _deeplink_recommendations(scheme, findings),
    }


def _deeplink_recommendations(scheme: str, findings: list[dict]) -> list[str]:
    recs = []
    titles = " ".join(f["title"] for f in findings).lower()
    if scheme in _CRITICAL_SCHEMES:
        recs.append(f"Never open `{scheme}:` URIs from untrusted sources - they can execute code on your device.")
    if "intent" in titles:
        recs.append("Avoid tapping intent:// links from messages or web pages. Open apps directly from your home screen.")
    if "market" in titles:
        recs.append("Do not install apps prompted by links in messages. Only install apps from the official store directly.")
    if "token" in titles or "oauth" in titles:
        recs.append("A deep link containing OAuth tokens is almost always a phishing redirect. Do not proceed.")
    if "open redirect" in titles:
        recs.append("This link redirects to another URL. Verify the final destination before proceeding.")
    if not recs:
        recs.append("Only open deep links from known, trusted sources. Verify the destination app is legitimate.")
    return recs


# ── 3. Mobile URL analysis ──────────────────────────────────────────────────────

def analyze_mobile_url(url: str) -> dict:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed   = urlparse(url)
    host     = (parsed.hostname or "").lower().lstrip("www.")
    path     = parsed.path.lower()
    full     = (host + path).lower()
    findings: list[dict] = []
    score    = 0

    # URL shortener
    if _is_shortener(url):
        score += 35
        findings.append({
            "severity": "high",
            "title": "URL Shortener - Destination Hidden",
            "detail": f"Domain `{host}` is a URL shortening service. "
                      "Smishing campaigns almost exclusively use shorteners to hide phishing domains.",
        })

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 25
            findings.append({
                "severity": "high",
                "title": f"High-Risk TLD: `{tld}`",
                "detail": f"The `{tld}` TLD is heavily associated with free/disposable phishing domains.",
            })
            break

    # Mobile-specific path patterns (tracking links, short redirect paths)
    if _MOBILE_PATH_RE.match(path):
        score += 15
        findings.append({
            "severity": "medium",
            "title": "Mobile Campaign Tracking Path Pattern",
            "detail": f"Path `{path[:60]}` matches common smishing campaign redirect structures.",
        })

    # Phishing keywords in host/path
    kw_hits = _MOBILE_SUSPICIOUS_KEYWORDS.findall(full)
    if len(kw_hits) >= 2:
        score += 20
        findings.append({
            "severity": "high",
            "title": f"Multiple Phishing Keywords in URL ({len(kw_hits)})",
            "detail": f"Keywords detected: {', '.join(set(k.lower() for k in kw_hits[:6]))}",
        })
    elif len(kw_hits) == 1:
        score += 10

    # Numeric IP as hostname
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        score += 30
        findings.append({
            "severity": "high",
            "title": "IP Address Host",
            "detail": f"URL hosted on raw IP {host}. Legitimate mobile-targeted services always use domain names.",
        })

    # No HTTPS
    if parsed.scheme == 'http':
        score += 15
        findings.append({
            "severity": "medium",
            "title": "HTTP - No Encryption",
            "detail": "Unencrypted link. Mobile login pages must use HTTPS; HTTP links in SMS are always suspicious.",
        })

    # Very long subdomain chain (subdomain stuffing)
    subdomain_parts = host.split(".")
    if len(subdomain_parts) > 4:
        score += 15
        findings.append({
            "severity": "medium",
            "title": "Subdomain Stuffing",
            "detail": f"Host has {len(subdomain_parts) - 2} subdomain level(s). "
                      "Attackers add legitimate brand names as subdomains to appear trustworthy: "
                      f"`brand.legitimatesite.evil.com`.",
        })

    # Brand name as subdomain of unrelated domain
    brand_in_subdomain = False
    if len(subdomain_parts) > 2:
        sub_str = ".".join(subdomain_parts[:-2])
        _, brand_name = _detect_brand(sub_str)
        root_domain = ".".join(subdomain_parts[-2:])
        _, root_brand = _detect_brand(root_domain)
        if brand_name and not root_brand:
            brand_in_subdomain = True
            score += 35
            findings.append({
                "severity": "critical",
                "title": f"Brand Name as Subdomain - `{brand_name}`",
                "detail": f"`{brand_name}` appears as a subdomain of `{root_domain}`. "
                          "This is a common technique to make phishing URLs look legitimate at a glance.",
            })

    return {
        "url": url,
        "risk_score": _risk_10(score),
        "threat_type": "Mobile Phishing URL" if findings else None,
        "findings": findings,
        "recommendations": _mobile_url_recommendations(findings),
    }


def _mobile_url_recommendations(findings: list[dict]) -> list[str]:
    recs = []
    titles = " ".join(f["title"] for f in findings).lower()
    if "shortener" in titles:
        recs.append("Expand shortened URLs before tapping. Use a URL expander (e.g. checkshorturl.com) to preview the destination.")
    if "brand name as subdomain" in titles:
        recs.append("Verify the root domain (after the last dot before the path). Subdomains do not indicate legitimacy.")
    if "ip address" in titles:
        recs.append("Legitimate services do not use raw IP addresses in links sent to users.")
    if "keyword" in titles or "tld" in titles:
        recs.append("This URL has characteristics common in smishing landing pages. Do not enter any credentials.")
    if not recs:
        recs.append("Verify the URL's root domain is the official one before entering any information.")
    return recs
