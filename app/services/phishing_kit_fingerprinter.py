"""Phishing Kit Fingerprinter - orchestration layer."""
from html.parser import HTMLParser

import httpx

from app.utils.ssrf_guard import is_safe_url
from app.services.kit_signatures import PHISHING_KITS, score_kit
from app.services.kit_heuristics import build_indicators, compute_risk_score


# ── HTML extraction ─────────────────────────────────────────────────────────────

class _HTMLExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms:   list[dict] = []
        self.scripts: list[str]  = []
        self.links:   list[str]  = []
        self.inputs:  list[dict] = []
        self.title:   str        = ""
        self._in_title  = False
        self._in_script = False
        self._cur_script = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append(a)
        elif tag == "script":
            self._in_script  = True
            self._cur_script = ""
            if a.get("src"):
                self.links.append(a["src"])
        elif tag in ("a", "link"):
            if a.get("href"):
                self.links.append(a["href"])
        elif tag == "input":
            self.inputs.append(a)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.scripts.append(self._cur_script)
            self._in_script = False
            self._cur_script = ""
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:   self.title += data
        if self._in_script:  self._cur_script += data


# ── HTTP fetch ──────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 12) -> tuple[str, str, dict]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    with httpx.Client(follow_redirects=True, timeout=timeout, verify=True) as client:
        resp = client.get(url, headers=headers)
        return resp.text, str(resp.url), dict(resp.headers)


# ── Public entry point ──────────────────────────────────────────────────────────

def fingerprint_url(url: str) -> dict:
    safe, reason = is_safe_url(url)
    if not safe:
        return {"error": reason, "url": url}

    try:
        html, final_url, _ = _fetch(url)
    except Exception as exc:
        return {"error": f"Fetch failed: {exc}", "url": url}

    html_lower = html.lower()
    ex = _HTMLExtractor()
    try:
        ex.feed(html)
    except Exception:
        pass
    js_body = " ".join(ex.scripts)

    # Kit matching
    scores: dict[str, int] = {
        kid: s
        for kid, kit in PHISHING_KITS.items()
        if (s := score_kit(kit, html_lower, js_body, final_url)) > 0
    }
    matched_kit  = max(scores, key=lambda k: scores[k]) if scores else None
    kit_conf     = min(100, int(scores[matched_kit] * 1.05)) if matched_kit else 0
    kit_info     = PHISHING_KITS[matched_kit] if matched_kit else {}
    kit_meta     = {k: kit_info[k] for k in ("description", "category", "targets", "threat_actors", "first_seen")} if kit_info else None

    # Heuristic indicators
    indicators = build_indicators(html, html_lower, js_body, ex.inputs, url, final_url)

    pw_inputs = [i for i in ex.inputs
                 if any(t in (i.get("name", "") + i.get("type", "") + i.get("id", "")).lower()
                        for t in ("password", "passwd", "pwd", "pin"))]

    risk_score = compute_risk_score(indicators, kit_conf, bool(pw_inputs), bool(matched_kit))

    return {
        "url":            url,
        "final_url":      final_url,
        "matched_kit":    matched_kit,
        "kit_confidence": kit_conf,
        "kit_meta":       kit_meta,
        "risk_score":     risk_score,
        "indicators":     indicators,
        "structure": {
            "title":              ex.title.strip()[:120],
            "form_count":         len(ex.forms),
            "input_count":        len(ex.inputs),
            "script_count":       len(ex.scripts),
            "password_fields":    len(pw_inputs),
            "email_fields":       sum(1 for i in ex.inputs
                                      if any(t in (i.get("name","") + i.get("type","") + i.get("id","")).lower()
                                             for t in ("email", "user", "login"))),
            "card_fields":        sum(1 for i in ex.inputs
                                      if any(t in (i.get("name","") + i.get("id","")).lower()
                                             for t in ("card", "cvv", "cvc", "expir"))),
            "otp_fields":         sum(1 for i in ex.inputs
                                      if any(t in (i.get("name","") + i.get("id","")).lower()
                                             for t in ("otp", "totp", "mfa", "sms"))),
            "has_telegram_exfil": any(i["type"] == "exfil_telegram" for i in indicators),
            "has_discord_exfil":  any(i["type"] == "exfil_discord"  for i in indicators),
            "has_antibot":        any(i["type"] == "antibot"         for i in indicators),
            "has_obfuscation":    any(i["type"] == "obfuscation"     for i in indicators),
            "page_size_bytes":    len(html.encode("utf-8", errors="replace")),
            "external_links":     [l for l in ex.links if l.startswith("http")][:12],
        },
        "kit_scores": dict(sorted(scores.items(), key=lambda x: -x[1])),
    }
