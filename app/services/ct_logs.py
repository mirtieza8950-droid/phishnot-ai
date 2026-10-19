"""
Certificate Transparency log scanner.

Queries crt.sh (Sectigo's public CT log index) for all SSL/TLS certificates
that contain a brand name. Deduplicates by domain, risk-scores each entry,
and returns results sorted highest-risk first.

No API key required. crt.sh is a free public service.
"""

import re
import httpx

_CT_URL = "https://crt.sh/"

_PHISH_KEYWORDS = [
    "login", "secure", "verify", "account", "update", "signin",
    "support", "confirm", "banking", "wallet", "invoice", "payment",
    "alert", "notification", "recovery", "reset", "activate", "auth",
    "portal", "service", "helpdesk", "validation",
]

_RISKY_TLDS = {
    ".xyz", ".top", ".online", ".site", ".live", ".club",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".icu", ".vip", ".fun", ".space", ".cyou",
}


def _risk_score(domain: str) -> int:
    score = 0
    if any(kw in domain for kw in _PHISH_KEYWORDS):
        score += 3
    if "-" in domain:
        score += 1
    if any(domain.endswith(t) for t in _RISKY_TLDS):
        score += 2
    if "xn--" in domain:  # punycode / IDN - high risk
        score += 4
    return min(score, 10)


def _short_issuer(issuer_dn: str) -> str:
    """Extract O= field from a DN string, fall back to truncated raw."""
    m = re.search(r"O=([^,]+)", issuer_dn or "")
    return m.group(1).strip() if m else (issuer_dn or "")[:40]


def _extract_domains(entry: dict) -> list[str]:
    """
    Pull every unique hostname out of an entry's common_name + name_value.
    Wildcards are stripped for deduplication but kept for display.
    """
    raw = set()
    for field in ("common_name", "name_value"):
        val = (entry.get(field) or "").strip()
        for part in val.split("\n"):
            part = part.strip().lower()
            if part:
                raw.add(part)
    return sorted(raw)


def query_ct_logs(brand_domain: str, max_results: int = 300) -> dict:
    """
    Query crt.sh for certificates containing the brand label.

    brand_domain: full domain, e.g. "paypal.com"
    Returns a dict with: brand, domain, total, results (list)
    """
    brand_domain = brand_domain.strip().lower().lstrip("www.")
    parts = brand_domain.split(".")
    label = parts[0]  # e.g. "paypal"

    try:
        resp = httpx.get(
            _CT_URL,
            params={"q": f"%{label}%", "output": "json"},
            timeout=20.0,
            headers={"Accept": "application/json", "User-Agent": "PhishGuard/1.0"},
            follow_redirects=True,
        )
        resp.raise_for_status()
        raw_entries = resp.json()
    except httpx.TimeoutException:
        return {"error": "crt.sh timed out - try again in a moment", "results": [], "total": 0}
    except Exception as e:
        return {"error": str(e), "results": [], "total": 0}

    if not isinstance(raw_entries, list):
        return {"error": "Unexpected response from crt.sh", "results": [], "total": 0}

    # Deduplicate by clean domain, keeping the entry with the most recent not_before
    best: dict[str, dict] = {}  # clean_domain -> best entry

    for entry in raw_entries:
        for domain in _extract_domains(entry):
            clean = domain.lstrip("*.")

            # Must contain the brand label
            if label not in clean:
                continue

            # Skip the legitimate domain and its subdomains
            if clean == brand_domain or clean.endswith(f".{brand_domain}"):
                continue

            # Basic domain validity
            if not re.match(r"^[a-z0-9*.\-]+$", domain):
                continue

            # Keep the most recent issuance per unique clean domain
            if clean not in best or (entry.get("not_before", "") or "") > (best[clean].get("not_before", "") or ""):
                best[clean] = {
                    "domain":     domain,
                    "clean":      clean,
                    "not_before": (entry.get("not_before") or "")[:19],
                    "not_after":  (entry.get("not_after")  or "")[:19],
                    "issuer":     _short_issuer(entry.get("issuer_name", "")),
                    "id":         entry.get("id"),
                    "risk":       _risk_score(clean),
                }

    # Sort: risk descending, then most recent first
    results = sorted(
        best.values(),
        key=lambda x: (-x["risk"], x.get("not_before", "")),
        reverse=True,
    )

    # Remove internal 'clean' key from output
    for r in results:
        r.pop("clean", None)

    return {
        "brand":   label,
        "domain":  brand_domain,
        "total":   len(results),
        "results": results[:max_results],
    }
