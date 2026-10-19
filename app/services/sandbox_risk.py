"""
Sandbox risk assessment - combination-based model.

Core principle: signals are only meaningful in the context of credential theft.
A cross-origin POST on a page with no password form is analytics.
Minified JS with atob() is normal. DOM mutations are normal in any SPA.

We score COMBINATIONS, not individual signals. This eliminates false positives
on sites like Google and Bing while still catching real phishing pages.
"""
from urllib.parse import urlparse


# ── Domain helpers ─────────────────────────────────────────────────────────────

def _root_domain(netloc: str) -> str:
    """Reduce netloc to eTLD+1: accounts.google.com -> google.com."""
    host  = netloc.split(":")[0].lower().lstrip("www.")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _same_site(a: str, b: str) -> bool:
    """True when both netlocs share the same eTLD+1."""
    return bool(a) and bool(b) and _root_domain(a) == _root_domain(b)


# ── Main assessor ──────────────────────────────────────────────────────────────

def assess_risk(result: dict) -> dict:
    findings: list[dict] = []
    score      = 0
    dom        = result.get("dom") or {}
    net        = result.get("network") or {}
    url_origin = urlparse(result.get("url", "")).netloc

    # ── Gather page facts (no scoring yet) ───────────────────────────────────

    forms     = dom.get("forms", [])
    pw_forms  = [f for f in forms if f.get("has_password")]
    has_creds = len(pw_forms) > 0

    # Is any password form's action pointing at a genuinely different domain?
    cross_domain_actions = []
    for form in pw_forms:
        action      = form.get("action", "")
        action_host = urlparse(action).netloc if action.startswith("http") else ""
        if action_host and not _same_site(url_origin, action_host):
            cross_domain_actions.append(action_host)

    # Cross-origin POST/PUT/PATCH requests to genuinely external domains
    # (same-site POSTs - analytics to bat.bing.com, accounts.google.com, etc. - are excluded)
    external_posts = [
        r for r in net.get("data_exfil_candidates", [])
        if not _same_site(url_origin, urlparse(r["url"]).netloc)
    ]

    # JS obfuscation: count DISTINCT techniques (single technique = minification)
    obfusc_techs = [t for t, present in [
        ("eval()",        dom.get("has_eval")),
        ("document.write()", dom.get("has_doc_write")),
        ("atob()/btoa()", dom.get("has_base64")),
    ] if present]

    iframes  = dom.get("iframes", [])
    dialogs  = result.get("dialogs") or []
    meta_ref = dom.get("meta_refresh") or []

    # ── Score combinations ─────────────────────────────────────────────────────
    #
    # Rule of thumb:
    #   • Signal alone          -> 0-10 pts  (informational; any site can trigger)
    #   • Signal + credentials  -> add 20-35 (context makes it meaningful)
    #   • Classic phishing combo -> 40-60 pts (two or more key signals together)

    # 1. Password form
    if has_creds:
        score += 10
        if cross_domain_actions:
            # Form submits to unrelated domain - classic phishing pattern
            score += 40
            for host in cross_domain_actions[:2]:
                findings.append({
                    "severity": "critical",
                    "title": "Cross-domain credential form",
                    "detail": f"Password form POSTs to unrelated domain: {host}",
                })
        else:
            first = pw_forms[0]
            findings.append({
                "severity": "high",
                "title": "Login / password form detected",
                "detail": (
                    f"{first['input_count']} input(s) including password field. "
                    f"Action: {(first.get('action') or 'same-page')[:80]}"
                ),
            })

    # 2. External POSTs
    #    Without credentials on the page: almost certainly third-party analytics -> +3
    #    With credentials: strong exfiltration signal -> +25
    if external_posts:
        if has_creds:
            score += 25
            for r in external_posts[:2]:
                findings.append({
                    "severity": "critical",
                    "title": f"Cross-origin {r['method']} on credential page",
                    "detail": f"Possible data exfiltration: {r['url'][:140]}",
                })
        else:
            score += 3  # analytics/tracking - no credential context

    # 3. JS obfuscation
    #    Single technique: all minified JS has this -> not scored
    #    Two or more: meaningful; weight doubles if credentials are present
    if len(obfusc_techs) >= 2:
        if has_creds:
            score += 20
            findings.append({
                "severity": "high",
                "title": "JavaScript obfuscation on credential page",
                "detail": f"Multiple techniques in inline scripts: {', '.join(obfusc_techs)}",
            })
        else:
            score += 8
            findings.append({
                "severity": "medium",
                "title": "JavaScript obfuscation detected",
                "detail": f"Techniques: {', '.join(obfusc_techs)} - common in minified code but worth noting.",
            })

    # 4. Meta-refresh (always suspicious; especially with credentials)
    if meta_ref:
        score += 15
        if has_creds:
            score += 10
        findings.append({
            "severity": "high",
            "title": "Meta-refresh redirect in page HTML",
            "detail": f"content: {meta_ref[0][:80]}",
        })

    # 5. Browser dialogs / scareware
    if dialogs:
        score += 15
        if has_creds:
            score += 10
        findings.append({
            "severity": "high",
            "title": f"{len(dialogs)} browser dialog(s) triggered",
            "detail": "; ".join(d["message"][:60] for d in dialogs[:2]),
        })

    # 6. Iframes
    #    Iframes alone: common for ads/widgets -> low score
    #    Iframes + credentials: overlay-phishing pattern -> higher score
    if iframes:
        if has_creds:
            score += 15
            findings.append({
                "severity": "high",
                "title": f"{len(iframes)} iframe(s) on credential page",
                "detail": "; ".join(f.get("src", "")[:60] for f in iframes[:3]),
            })
        else:
            score += 3
            findings.append({
                "severity": "low",
                "title": f"{len(iframes)} iframe(s) embedded",
                "detail": "; ".join(f.get("src", "")[:60] for f in iframes[:3]),
            })

    # 7. Storage access - purely informational, no score impact
    if dom.get("storage_access"):
        findings.append({
            "severity": "low",
            "title": f"Browser storage accessed ({len(dom['storage_access'])} operations)",
            "detail": ", ".join({a["s"] for a in dom["storage_access"]}),
        })

    # ── Signals intentionally NOT scored ──────────────────────────────────────
    #   DOM mutations     - every React/Vue/Angular SPA generates hundreds
    #   Single obfusc     - all minified JavaScript triggers this
    #   Cross-origin CDN  - every modern site loads scripts from CDNs
    #   www redirect      - google.com->www.google.com is not suspicious

    score = min(score, 100)
    level = (
        "Critical" if score >= 70 else
        "High"     if score >= 45 else
        "Medium"   if score >= 20 else
        "Low"
    )
    return {"score": score, "level": level, "findings": findings}
