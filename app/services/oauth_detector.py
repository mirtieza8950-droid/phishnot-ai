"""
OAuth / Token Theft Detection Engine.

Static analysis - no network calls. Covers:
  1. Fake OAuth provider impersonation (typosquatting of consent-screen domains)
  2. Token / authorization-code exposure inside URLs
  3. JWT token presence in URLs or email text
  4. Dangerous / overprivileged scope combinations
  5. Suspicious redirect_uri targets
  6. AiTM proxy / session-hijacking indicators in OAuth flows
  7. Consent-phishing patterns in email body text
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from difflib import SequenceMatcher


# ── Known legitimate OAuth authorization endpoints ──────────────────────────────

KNOWN_PROVIDERS: dict[str, dict] = {
    "accounts.google.com": {
        "name": "Google",
        "paths": ["/o/oauth2/v2/auth", "/o/oauth2/auth"],
    },
    "login.microsoftonline.com": {
        "name": "Microsoft",
        "paths": ["/common/oauth2/v2.0/authorize", "/common/oauth2/authorize",
                  "/organizations/oauth2/v2.0/authorize"],
    },
    "login.live.com": {"name": "Microsoft Live", "paths": ["/oauth20_authorize.srf"]},
    "github.com":     {"name": "GitHub",   "paths": ["/login/oauth/authorize"]},
    "www.facebook.com": {"name": "Facebook", "paths": ["/dialog/oauth", "/v*/dialog/oauth"]},
    "facebook.com":   {"name": "Facebook", "paths": ["/dialog/oauth"]},
    "appleid.apple.com": {"name": "Apple", "paths": ["/auth/authorize"]},
    "twitter.com":    {"name": "Twitter/X", "paths": ["/i/oauth2/authorize"]},
    "api.twitter.com": {"name": "Twitter/X", "paths": ["/oauth/authorize"]},
    "www.linkedin.com": {"name": "LinkedIn", "paths": ["/oauth/v2/authorization"]},
    "discord.com":    {"name": "Discord", "paths": ["/oauth2/authorize"]},
    "slack.com":      {"name": "Slack",   "paths": ["/oauth/v2/authorize", "/oauth/authorize"]},
    "id.twitch.tv":   {"name": "Twitch",  "paths": ["/oauth2/authorize"]},
    "www.reddit.com": {"name": "Reddit",  "paths": ["/api/v1/authorize"]},
    "api.instagram.com": {"name": "Instagram", "paths": ["/oauth/authorize"]},
    "gitlab.com":     {"name": "GitLab",  "paths": ["/oauth/authorize"]},
    "bitbucket.org":  {"name": "Bitbucket", "paths": ["/site/oauth2/authorize"]},
    "zoom.us":        {"name": "Zoom",    "paths": ["/oauth/authorize"]},
    "dropbox.com":    {"name": "Dropbox", "paths": ["/oauth2/authorize"]},
    "api.dropbox.com": {"name": "Dropbox", "paths": ["/1/oauth2/authorize"]},
    "salesforce.com": {"name": "Salesforce", "paths": ["/services/oauth2/authorize"]},
    "login.salesforce.com": {"name": "Salesforce", "paths": ["/services/oauth2/authorize"]},
}

# Brand names used to check for impersonation even when the full domain differs
_PROVIDER_BRANDS = {
    "google": "accounts.google.com",
    "microsoft": "login.microsoftonline.com",
    "github": "github.com",
    "facebook": "facebook.com",
    "apple": "appleid.apple.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "discord": "discord.com",
    "slack": "slack.com",
}

# ── Dangerous OAuth scopes ──────────────────────────────────────────────────────

_SCOPE_RISK: dict[str, str] = {
    # Google critical
    "https://www.googleapis.com/auth/gmail.modify":               "critical",
    "https://www.googleapis.com/auth/gmail.readonly":             "high",
    "https://www.googleapis.com/auth/gmail.compose":              "high",
    "https://www.googleapis.com/auth/gmail.send":                 "high",
    "https://www.googleapis.com/auth/admin.directory.user":       "critical",
    "https://www.googleapis.com/auth/admin.directory.group":      "critical",
    "https://www.googleapis.com/auth/drive":                      "high",
    "https://www.googleapis.com/auth/drive.readonly":             "medium",
    "https://www.googleapis.com/auth/contacts":                   "medium",
    "https://www.googleapis.com/auth/calendar":                   "medium",
    "https://www.googleapis.com/auth/cloud-platform":             "critical",
    # Microsoft
    "mail.readwrite":          "high",
    "mail.send":               "high",
    "calendars.readwrite":     "medium",
    "files.readwrite.all":     "high",
    "user.readwrite.all":      "critical",
    "directory.readwrite.all": "critical",
    "rolesmanagement.readwrite.all": "critical",
    "application.readwrite.all":    "critical",
    # GitHub
    "repo":              "high",
    "repo:status":       "medium",
    "repo:deployment":   "medium",
    "admin:org":         "critical",
    "admin:repo_hook":   "high",
    "admin:public_key":  "high",
    "delete_repo":       "critical",
    "write:packages":    "high",
    "admin:gpg_key":     "medium",
    "workflow":          "high",
    # Generic high-risk keywords
    "admin":             "critical",
    "sudo":              "critical",
    "superuser":         "critical",
    "root":              "critical",
    "manage":            "high",
    "delete":            "high",
    "write:all":         "critical",
    "read:all":          "high",
    "offline_access":    "medium",
    "offline":           "medium",
    "full":              "high",
    "all":               "high",
}

# ── Token / secret patterns ─────────────────────────────────────────────────────

_TOKEN_URL_PARAMS = {
    "access_token":   "critical",
    "id_token":       "critical",
    "refresh_token":  "critical",
    "token":          "high",
    "bearer":         "critical",
    "api_key":        "high",
    "apikey":         "high",
    "secret":         "high",
    "client_secret":  "critical",
    "password":       "critical",
    "passwd":         "critical",
    "session":        "high",
    "session_token":  "critical",
    "auth_token":     "critical",
}

_JWT_RE     = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
_CODE_RE    = re.compile(r'[?&]code=[A-Za-z0-9._~-]{10,}')
_BEARER_RE  = re.compile(r'\bBearer\s+[A-Za-z0-9._~+/=-]{20,}', re.I)
_OAUTH_URL_RE = re.compile(
    r'https?://[^\s<>"\']+(?:oauth|authorize|auth|login|signin)[^\s<>"\']*',
    re.I,
)

_SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work',
    '.buzz', '.surf', '.fit', '.link', '.click', '.zip', '.mov',
}

# Consent-phishing language patterns in email body
_CONSENT_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"(grant|authorize|allow|approve|give)\s+(access|permission|consent)",
        r"(click|tap|press)\s+(here|this link|the link|below).{0,40}(authorize|grant|connect)",
        r"(your|the)\s+(account|data|information)\s+(has been|is)\s+(compromised|accessed|breached)",
        r"verify\s+(your|account)\s+(identity|ownership|access)",
        r"oauth.{0,30}(consent|permission|authorize)",
        r"(microsoft|google|github|slack).{0,30}(app|application)\s+(request|want|need).{0,30}(access|permission)",
    ]
]

# AiTM proxy indicators in OAuth URLs
_AITM_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"evilginx",
        r"phishlet",
        r"modlishka",
        r"muraena",
        r"tycoon",
        r"aitm",
        r"realtime.auth",
        r"live-auth\.",
        r"secure-oauth\.",
    ]
]


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _root_domain(host: str) -> str:
    parts = host.lower().lstrip("www.").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _is_suspicious_tld(host: str) -> bool:
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return True
    return False


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _scope_risk(scope_str: str) -> list[dict]:
    """Return list of {scope, risk} for all scopes that match the danger list."""
    scopes = re.split(r"[\s,+]+", scope_str.strip())
    risky: list[dict] = []
    for s in scopes:
        s_lower = s.lower()
        # Direct match
        if s_lower in _SCOPE_RISK:
            risky.append({"scope": s, "risk": _SCOPE_RISK[s_lower]})
            continue
        # Keyword match for full URL scopes
        for key, risk in _SCOPE_RISK.items():
            if key in s_lower and len(key) > 4:
                risky.append({"scope": s, "risk": risk})
                break
    return risky


def _detect_impersonation(host: str) -> dict | None:
    """Check if host is a typosquatted version of a known OAuth provider."""
    host_lower = host.lower()

    # Exact match -> legitimate
    if host_lower in KNOWN_PROVIDERS:
        return None

    root = _root_domain(host_lower)

    # Check similarity against each known provider brand
    for brand, legit_host in _PROVIDER_BRANDS.items():
        legit_root = _root_domain(legit_host)

        # Brand name appears in host but domain doesn't match exactly
        if brand in host_lower and root != legit_root:
            return {
                "impersonates": KNOWN_PROVIDERS.get(legit_host, {}).get("name", brand.title()),
                "legitimate_host": legit_host,
                "similarity": round(_similarity(root, legit_root), 2),
                "method": "brand_name_in_foreign_domain",
            }

        # High character similarity (typosquatting)
        sim = _similarity(root, legit_root)
        if sim >= 0.80 and root != legit_root:
            return {
                "impersonates": KNOWN_PROVIDERS.get(legit_host, {}).get("name", brand.title()),
                "legitimate_host": legit_host,
                "similarity": round(sim, 2),
                "method": "typosquatting",
            }

    return None


# ── Core analysis functions ─────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Full static analysis of a single URL for OAuth/token-theft indicators.
    Returns a structured result dict.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed  = urlparse(url)
    host    = (parsed.hostname or "").lower()
    params  = parse_qs(parsed.query, keep_blank_values=True)
    flat    = {k: (v[0] if v else "") for k, v in params.items()}
    full_url_decoded = unquote(url)

    findings: list[dict] = []
    score = 0

    # ── 1. Provider identification ───────────────────────────────────────────
    provider_name = None
    provider_legitimate = False

    if host in KNOWN_PROVIDERS:
        provider_name       = KNOWN_PROVIDERS[host]["name"]
        provider_legitimate = True
    else:
        impersonation = _detect_impersonation(host)
        if impersonation:
            provider_name = f"{impersonation['impersonates']} (FAKE)"
            score += 60
            findings.append({
                "severity": "critical",
                "title": f"OAuth Provider Impersonation - {impersonation['impersonates']}",
                "detail": (
                    f"Domain '{host}' impersonates '{impersonation['legitimate_host']}' "
                    f"via {impersonation['method']} "
                    f"(similarity {impersonation['similarity']:.0%})."
                ),
            })

    # ── 2. Is this an OAuth / auth URL at all? ───────────────────────────────
    is_oauth = bool(
        any(k in flat for k in ("response_type", "client_id", "scope", "redirect_uri",
                                "grant_type", "code", "access_token", "id_token"))
        or re.search(r"/(oauth|authorize|auth|connect)[/\?]", parsed.path, re.I)
    )

    # ── 3. Token / code exposure ─────────────────────────────────────────────
    tokens_found: list[dict] = []

    for param, risk in _TOKEN_URL_PARAMS.items():
        if param in flat and flat[param]:
            val = flat[param]
            tokens_found.append({"param": param, "value": val[:30] + "..." if len(val) > 30 else val, "risk": risk})
            pts = 50 if risk == "critical" else 35
            score += pts
            findings.append({
                "severity": risk,
                "title": f"OAuth token exposed in URL - `{param}`",
                "detail": (
                    f"The `{param}` value appears in the URL as a query parameter. "
                    "Tokens in URLs appear in server logs, browser history, and HTTP Referer headers - "
                    "a classic channel for token theft."
                ),
            })

    # Authorization code in URL
    if "code" in flat and flat["code"] and not provider_legitimate:
        score += 40
        findings.append({
            "severity": "critical",
            "title": "Authorization code delivered to suspicious domain",
            "detail": (
                f"An OAuth authorization code (`code={flat['code'][:20]}...`) is being sent to '{host}', "
                "which is not a recognized OAuth provider. Attackers intercept these codes to obtain access tokens."
            ),
        })
        tokens_found.append({"param": "code", "value": flat["code"][:20] + "...", "risk": "critical"})
    elif "code" in flat and flat["code"] and provider_legitimate:
        # Code at legitimate provider is normal (callback), just note it
        tokens_found.append({"param": "code", "value": flat["code"][:20] + "...", "risk": "low"})

    # JWT anywhere in URL
    jwt_matches = _JWT_RE.findall(full_url_decoded)
    if jwt_matches:
        score += 45
        for jwt in jwt_matches[:3]:
            tokens_found.append({"param": "jwt_in_url", "value": jwt[:40] + "...", "risk": "critical"})
        findings.append({
            "severity": "critical",
            "title": f"JWT token(s) embedded in URL ({len(jwt_matches)} found)",
            "detail": (
                "JSON Web Tokens in URLs are a serious security risk. "
                "They leak into logs, history, and Referer headers. "
                "This is a common indicator of token-theft redirects."
            ),
        })

    # ── 4. Scope analysis ────────────────────────────────────────────────────
    scope_str     = flat.get("scope", "")
    risky_scopes  = _scope_risk(scope_str) if scope_str else []
    all_scopes    = re.split(r"[\s,+]+", scope_str.strip()) if scope_str else []

    if risky_scopes:
        critical_scopes = [s for s in risky_scopes if s["risk"] == "critical"]
        high_scopes     = [s for s in risky_scopes if s["risk"] == "high"]

        if critical_scopes:
            score += 35
            findings.append({
                "severity": "critical",
                "title": f"Critically overprivileged OAuth scopes ({len(critical_scopes)})",
                "detail": f"Critical-risk scopes requested: {', '.join(s['scope'] for s in critical_scopes[:5])}",
            })
        if high_scopes:
            score += 20
            findings.append({
                "severity": "high",
                "title": f"High-risk OAuth scopes ({len(high_scopes)})",
                "detail": f"High-risk scopes requested: {', '.join(s['scope'] for s in high_scopes[:5])}",
            })

    # ── 5. Redirect URI analysis ─────────────────────────────────────────────
    redirect_uri   = flat.get("redirect_uri", "")
    redirect_flags = []

    if redirect_uri:
        r_parsed = urlparse(unquote(redirect_uri))
        r_host   = (r_parsed.hostname or "").lower()

        if r_host and r_parsed.scheme != "https" and r_host != "localhost":
            redirect_flags.append("non-HTTPS redirect_uri")
            score += 15
        if _is_ip(r_host):
            redirect_flags.append("IP address redirect_uri")
            score += 25
        if _is_suspicious_tld(r_host):
            redirect_flags.append(f"suspicious TLD in redirect_uri ({r_host})")
            score += 20
        if r_host and r_host not in KNOWN_PROVIDERS and _detect_impersonation(r_host):
            redirect_flags.append("redirect_uri points to impersonation domain")
            score += 40
        # Open redirect: wildcard or relative path tricks
        if re.search(r"[?&]redirect_uri=.*(?:javascript:|data:|vbscript:)", url, re.I):
            redirect_flags.append("possible open-redirect injection in redirect_uri")
            score += 30

        if redirect_flags:
            findings.append({
                "severity": "high",
                "title": "Suspicious redirect_uri",
                "detail": f"Issues: {', '.join(redirect_flags)}. "
                          f"Destination: {redirect_uri[:120]}",
            })

    # ── 6. HTTPS check ───────────────────────────────────────────────────────
    if parsed.scheme != "https" and is_oauth:
        score += 20
        findings.append({
            "severity": "high",
            "title": "OAuth flow over HTTP (not HTTPS)",
            "detail": "Authorization requests and token exchanges must use HTTPS. "
                      "HTTP exposes tokens, codes, and state parameters to eavesdroppers.",
        })

    # ── 7. AiTM proxy indicators ─────────────────────────────────────────────
    for pat in _AITM_PATTERNS:
        if pat.search(full_url_decoded):
            score += 70
            findings.append({
                "severity": "critical",
                "title": "AiTM Phishing Proxy Indicator",
                "detail": f"URL matches pattern associated with adversary-in-the-middle frameworks "
                          f"(Evilginx, Modlishka, Tycoon 2FA, etc.). Session cookies may be stolen.",
            })
            break

    # ── 8. Suspicious host characteristics ──────────────────────────────────
    if _is_ip(host) and is_oauth:
        score += 30
        findings.append({
            "severity": "high",
            "title": "OAuth endpoint hosted on IP address",
            "detail": f"Authorization server at raw IP {host}. "
                      "Legitimate OAuth providers always use domain names.",
        })
    if _is_suspicious_tld(host) and is_oauth:
        score += 20
        findings.append({
            "severity": "medium",
            "title": f"OAuth endpoint on suspicious TLD",
            "detail": f"Host '{host}' uses a TLD commonly associated with free/phishing domains.",
        })

    # ── 9. Threat type classification ────────────────────────────────────────
    risk_score = min(10, round(score / 10))
    threat_type = None
    if any(f["title"].startswith("AiTM") for f in findings):
        threat_type = "AiTM Session Hijacking"
    elif any("Impersonation" in f["title"] for f in findings):
        threat_type = "OAuth Consent Phishing"
    elif any("token exposed" in f["title"].lower() or "JWT" in f["title"] for f in findings):
        threat_type = "Token Theft via URL Exposure"
    elif any("authorization code" in f["title"].lower() for f in findings):
        threat_type = "Authorization Code Interception"
    elif any("scope" in f["title"].lower() for f in findings):
        threat_type = "Privilege Escalation via OAuth Scopes"
    elif findings:
        threat_type = "Suspicious OAuth Activity"

    return {
        "url": url,
        "is_oauth_url": is_oauth,
        "risk_score": risk_score,
        "threat_type": threat_type,
        "provider": {
            "name": provider_name,
            "legitimate": provider_legitimate,
        },
        "oauth_params": {
            "response_type": flat.get("response_type"),
            "client_id": flat.get("client_id"),
            "scope": scope_str or None,
            "all_scopes": all_scopes,
            "risky_scopes": risky_scopes,
            "redirect_uri": redirect_uri or None,
            "redirect_uri_flags": redirect_flags,
            "state": flat.get("state"),
            "has_pkce": "code_challenge" in flat,
        },
        "tokens_found": tokens_found,
        "findings": findings,
        "recommendations": _recommendations(findings, provider_legitimate, risky_scopes),
    }


def analyze_email(text: str) -> dict:
    """
    Scan email body text for OAuth/token-theft indicators.
    Returns extracted URLs + per-URL analysis + overall verdict.
    """
    # Extract OAuth-like URLs
    raw_urls = _OAUTH_URL_RE.findall(text)
    # Also find any URL with token params
    raw_urls += re.findall(
        r'https?://[^\s<>"\']+(?:access_token|id_token|refresh_token|code=)[^\s<>"\']*', text, re.I
    )
    unique_urls = list(dict.fromkeys(u.rstrip(".,)>") for u in raw_urls))

    url_results = [analyze_url(u) for u in unique_urls[:20]]

    # Consent-phishing language
    consent_hits = [p.pattern for p in _CONSENT_PATTERNS if p.search(text)]

    # JWTs in email body
    jwts = _JWT_RE.findall(text)

    # Bearer tokens in email body
    bearers = _BEARER_RE.findall(text)

    body_findings: list[dict] = []
    body_score = 0

    if consent_hits:
        body_score += 25
        body_findings.append({
            "severity": "high",
            "title": "Consent-phishing language detected",
            "detail": f"Email contains language designed to trick users into granting OAuth access. "
                      f"Matched {len(consent_hits)} pattern(s).",
        })
    if jwts:
        body_score += 50
        body_findings.append({
            "severity": "critical",
            "title": f"{len(jwts)} JWT token(s) found in email body",
            "detail": "Hardcoded JWTs in email text may be stolen tokens shared to verify exfiltration.",
        })
    if bearers:
        body_score += 45
        body_findings.append({
            "severity": "critical",
            "title": f"{len(bearers)} Bearer token(s) found in email body",
            "detail": "Bearer tokens in email text represent stolen credential material.",
        })

    url_max_score = max((r["risk_score"] for r in url_results), default=0)
    overall = max(url_max_score, min(10, round(body_score / 10)))

    return {
        "urls_found": len(unique_urls),
        "url_analyses": url_results,
        "body_findings": body_findings,
        "jwts_in_body": len(jwts),
        "bearer_tokens_in_body": len(bearers),
        "consent_patterns_matched": len(consent_hits),
        "overall_risk_score": overall,
        "verdict": (
            "Critical - active token theft material detected" if overall >= 8 else
            "High - strong OAuth phishing indicators"         if overall >= 6 else
            "Medium - suspicious OAuth patterns"              if overall >= 3 else
            "Low - no significant OAuth threats detected"
        ),
    }


# ── Recommendations ─────────────────────────────────────────────────────────────

def _recommendations(findings: list[dict], provider_legit: bool, risky_scopes: list) -> list[str]:
    recs = []
    titles = " ".join(f["title"] for f in findings).lower()
    if "impersonation" in titles:
        recs.append("Verify the OAuth provider domain exactly - do not trust visual similarity to Google/Microsoft branding.")
    if "token exposed" in titles or "jwt" in titles:
        recs.append("Never follow links that include tokens in the URL. Report the link to your security team immediately.")
    if "authorization code" in titles:
        recs.append("Do not complete this OAuth flow. The authorization code is being delivered to an untrusted party.")
    if risky_scopes:
        recs.append("Carefully review all requested OAuth scopes. Legitimate apps rarely need admin, mail write, or delete permissions.")
    if "http" in titles:
        recs.append("Only complete OAuth flows over HTTPS. HTTP authorization requests expose your credentials.")
    if "aitm" in titles:
        recs.append("This URL matches a known AiTM phishing framework. Do not proceed - your session could be hijacked even with MFA.")
    if not recs:
        recs.append("Always verify the OAuth provider's domain before granting any application access to your account.")
    return recs
