"""DMARC / SPF / DKIM DNS lookup and parsing."""
import re
import socket


def _txt_records(name: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        return [b.decode() for rdata in answers for b in rdata.strings]
    except Exception:
        return []


def _has_a_record(domain: str) -> bool:
    try:
        socket.setdefaulttimeout(3)
        return len(socket.getaddrinfo(domain, None)) > 0
    except Exception:
        return False


def _parse_dmarc(records: list[str]) -> dict:
    for r in records:
        if r.startswith("v=DMARC1"):
            tags = dict(t.strip().split("=", 1) for t in r.split(";") if "=" in t)
            policy   = tags.get("p", "none").lower()
            strength = "strong" if policy == "reject" else "moderate" if policy == "quarantine" else "weak"
            return {
                "found": True, "raw": r, "policy": policy,
                "sp": tags.get("sp", policy).lower(),
                "pct": int(tags.get("pct", "100")),
                "rua": tags.get("rua", ""),
                "strength": strength, "tags": tags,
            }
    return {"found": False, "policy": None, "strength": "none", "raw": None, "tags": {}}


def _parse_spf(records: list[str]) -> dict:
    for r in records:
        if r.startswith("v=spf1"):
            has_all  = re.search(r"[~\-\+\?]all", r)
            redirect = re.search(r"redirect=([^\s]+)", r)
            qualifier = has_all.group(0)[0] if has_all else None
            strength  = "strong" if qualifier == "-" else "moderate" if qualifier == "~" else "weak"
            return {
                "found": True, "raw": r, "qualifier": qualifier,
                "strength": strength,
                "redirect": redirect.group(1) if redirect else None,
            }
    return {"found": False, "raw": None, "strength": "none", "qualifier": None}


def _check_dkim(domain: str) -> dict:
    for sel in ["default", "google", "mail", "dkim", "k1", "s1", "s2"]:
        for r in _txt_records(f"{sel}._domainkey.{domain}"):
            if "v=DKIM1" in r or "p=" in r:
                return {"found": True, "selector": sel, "raw": r[:120]}
    return {"found": False, "selector": None, "raw": None}


def brand_dns_check(domain: str) -> dict:
    domain = domain.strip().lower().lstrip("www.")
    dmarc  = _parse_dmarc(_txt_records(f"_dmarc.{domain}"))
    spf    = _parse_spf(_txt_records(domain))
    dkim   = _check_dkim(domain)
    score  = sum([
        1 if dmarc["strength"] in ("strong", "moderate") else 0,
        1 if spf["strength"]   in ("strong", "moderate") else 0,
        1 if dkim["found"] else 0,
    ])
    grade = "A" if score == 3 else "B" if score == 2 else "C" if score == 1 else "F"
    recommendations = []
    if not dmarc["found"]:
        recommendations.append("No DMARC record found. Add a DMARC policy to prevent email spoofing.")
    elif dmarc["strength"] == "weak":
        recommendations.append("DMARC policy is 'none'. Upgrade to 'quarantine' or 'reject'.")
    if not spf["found"]:
        recommendations.append("No SPF record found. Add an SPF record to authorise sending servers.")
    if not dkim["found"]:
        recommendations.append("No DKIM record found. Configure DKIM signing for outbound email.")
    return {
        "domain": domain, "dmarc": dmarc, "spf": spf, "dkim": dkim,
        "score": score, "grade": grade,
        "security_level": "Strong" if grade == "A" else "Moderate" if grade == "B" else "Weak" if grade == "C" else "None",
        "recommendations": recommendations,
    }
