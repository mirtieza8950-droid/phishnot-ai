"""Redirect chain tracer - checks SSRF guard on every hop, not just the first."""
from urllib.parse import urlparse

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
                  "buff.ly", "adf.ly", "rb.gy", "cutt.ly", "short.io"}


def trace_redirects(url: str, max_hops: int = 12, timeout: int = 6) -> dict:
    import requests
    from app.utils.ssrf_guard import is_safe_url

    chain, suspicious = [], []

    try:
        session = requests.Session()
        headers = {"User-Agent": "Mozilla/5.0 (PhishGuard Security Scanner/1.0)"}

        current_url = url
        for hop_num in range(max_hops + 1):
            # F-14: check EVERY hop before following, not just the initial URL
            safe, reason = is_safe_url(current_url)
            if not safe:
                chain.append({"url": current_url, "blocked": True, "reason": reason})
                suspicious.append(f"SSRF-blocked hop: {reason}")
                break

            resp = session.get(current_url, headers=headers, timeout=timeout,
                               allow_redirects=False)
            hop = {
                "url":         current_url,
                "status_code": resp.status_code,
                "domain":      urlparse(current_url).netloc,
            }
            chain.append(hop)
            _flag(hop, suspicious)

            if resp.is_redirect and resp.headers.get("Location"):
                next_url = resp.headers["Location"]
                # Resolve relative redirects
                if next_url.startswith("/"):
                    p = urlparse(current_url)
                    next_url = f"{p.scheme}://{p.netloc}{next_url}"
                current_url = next_url
            else:
                break   # no more redirects

        orig_domain  = urlparse(url).netloc
        final_domain = urlparse(current_url).netloc
        risk_score   = min(len(suspicious) * 20 + max(0, len(chain) - 3) * 5, 100)

        return {
            "original_url":    url,
            "final_url":       current_url,
            "hop_count":       len(chain) - 1,
            "chain":           chain,
            "suspicious_hops": list(dict.fromkeys(suspicious)),
            "domain_changed":  orig_domain != final_domain,
            "risk_score":      risk_score,
        }
    except Exception as exc:
        return {"original_url": url, "error": str(exc), "chain": chain,
                "suspicious_hops": suspicious, "hop_count": len(chain)}


def _flag(hop: dict, suspicious: list):
    domain = hop.get("domain", "").lower().lstrip("www.")
    url    = hop.get("url", "")
    if domain in URL_SHORTENERS:
        suspicious.append(f"URL shortener: {domain}")
    if "@" in url:
        suspicious.append("@ symbol in URL (obfuscation attempt)")
    if url.count(".") > 6:
        suspicious.append(f"Excessive subdomain depth: {domain}")
    if any(kw in url.lower() for kw in ["login", "verify", "secure", "account", "update", "confirm"]):
        suspicious.append(f"Phishing keyword in URL: {url[:80]}")
