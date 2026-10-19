"""Phase 4 - Email header forensics: SPF, DKIM, DMARC, hop analysis."""
from email.parser import HeaderParser


def parse_email_headers(raw_headers: str) -> dict:
    parser = HeaderParser()
    msg = parser.parsestr(raw_headers)

    auth_results = msg.get("Authentication-Results", "") or ""
    received_spf = msg.get("Received-SPF", "") or ""
    dkim_sig = msg.get("DKIM-Signature", "") or ""
    received_list = msg.get_all("Received") or []

    spf = _extract_result("spf", auth_results, received_spf)
    dkim = _extract_dkim(auth_results, dkim_sig)
    dmarc = _extract_result("dmarc", auth_results)

    from_addr = (msg.get("From") or "").lower()
    reply_to = (msg.get("Reply-To") or "").lower()
    return_path = (msg.get("Return-Path") or "").lower()

    red_flags = []
    if reply_to and reply_to != from_addr:
        red_flags.append("Reply-To differs from From address")
    from_domain = _extract_domain(from_addr)
    rp_domain = _extract_domain(return_path)
    if rp_domain and from_domain and rp_domain != from_domain:
        red_flags.append(f"Return-Path domain ({rp_domain}) != From domain ({from_domain})")
    if spf in ("fail", "softfail"):
        red_flags.append(f"SPF {spf} - sender not authorized by domain")
    if dkim == "fail":
        red_flags.append("DKIM signature verification failed")
    if dmarc == "fail":
        red_flags.append("DMARC policy not satisfied")
    hop_count = len(received_list)
    if hop_count > 10:
        red_flags.append(f"Unusual hop count ({hop_count} Received headers)")

    risk_score = 0
    if spf in ("fail", "softfail"):
        risk_score += 30
    if dkim == "fail":
        risk_score += 25
    if dmarc == "fail":
        risk_score += 25
    if reply_to and reply_to != from_addr:
        risk_score += 15
    if hop_count > 10:
        risk_score += 5
    if dkim == "none" and spf == "none":
        risk_score += 10

    return {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "hop_count": hop_count,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "red_flags": red_flags,
        "risk_score": min(risk_score, 100),
        "auth_results_raw": auth_results[:500] if auth_results else "",
    }


def _extract_result(key: str, auth_results: str, extra: str = "") -> str:
    combined = (auth_results + " " + extra).lower()
    for status in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
        if f"{key}={status}" in combined:
            return status
    return "none"


def _extract_dkim(auth_results: str, dkim_sig: str) -> str:
    lower = auth_results.lower()
    if "dkim=pass" in lower:
        return "pass"
    if "dkim=fail" in lower:
        return "fail"
    if dkim_sig:
        return "present"
    return "none"


def _extract_domain(addr: str) -> str:
    if "@" in addr:
        return addr.split("@")[-1].strip("<>").strip()
    return ""
