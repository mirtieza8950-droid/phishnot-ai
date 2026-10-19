"""
Threat Intelligence enrichment.

Queries three OSINT feeds in parallel (ThreadPoolExecutor, 6 s timeout each):
  1. VirusTotal v3  - multi-engine URL reputation   (requires VT_API_KEY)
  2. AlienVault OTX - open threat exchange pulses   (requires OTX_API_KEY)
  3. PhishTank      - verified phishing database    (optional PHISHTANK_APP_KEY)

Results are cached per-URL for one hour so the same scan never double-counts
against rate limits.  Unconfigured or errored feeds return gracefully without
blocking the other two.
"""

import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from app.core.config import settings

_TIMEOUT  = 6          # per-feed request timeout (seconds)
_TTL      = 3_600      # cache TTL (seconds)
_CACHE: dict[str, tuple[dict, float]] = {}

_VT_BASE  = "https://www.virustotal.com/api/v3"
_OTX_BASE = "https://otx.alienvault.com/api/v1"
_PT_URL   = "https://checkurl.phishtank.com/checkurl/"

_HEADERS_VT  = lambda: {"x-apikey": settings.VT_API_KEY}
_HEADERS_OTX = lambda: {"X-OTX-API-KEY": settings.OTX_API_KEY}


# ── VirusTotal ──────────────────────────────────────────────────────────────────

def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _check_virustotal(url: str) -> dict:
    if not settings.VT_API_KEY:
        return {"status": "unconfigured", "message": "Set VT_API_KEY in .env"}

    url_id = _vt_url_id(url)
    try:
        resp = requests.get(
            f"{_VT_BASE}/urls/{url_id}",
            headers=_HEADERS_VT(),
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"status": "not_found", "message": "URL not yet analysed by VirusTotal"}
        if resp.status_code == 429:
            return {"status": "rate_limited", "message": "VirusTotal rate limit - try again in a minute"}
        resp.raise_for_status()

        attr  = resp.json()["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious",  0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values())

        return {
            "status":         "found",
            "malicious":      mal,
            "suspicious":     sus,
            "harmless":       stats.get("harmless",   0),
            "undetected":     stats.get("undetected", 0),
            "total_engines":  total,
            "detection_rate": round(mal / total, 3) if total else 0,
            "categories":     list(attr.get("categories", {}).values())[:5],
            "last_analysis_date": attr.get("last_analysis_date"),
            "reputation":     attr.get("reputation", 0),
            "threat_level": (
                "malicious"  if mal >= 3 else
                "suspicious" if mal >= 1 or sus >= 3 else
                "clean"
            ),
            "report_url": f"https://www.virustotal.com/gui/url/{url_id}",
        }
    except requests.Timeout:
        return {"status": "timeout", "message": "VirusTotal request timed out"}
    except Exception:
        # F-34: do not include exc in message - it may contain the API key from request headers
        return {"status": "error", "message": "VirusTotal request failed"}


# ── AlienVault OTX ─────────────────────────────────────────────────────────────

def _check_otx(url: str) -> dict:
    if not settings.OTX_API_KEY:
        return {"status": "unconfigured", "message": "Set OTX_API_KEY in .env"}

    domain = (urlparse(url).hostname or "").lower()
    if not domain:
        return {"status": "error", "message": "Could not extract domain"}

    try:
        resp = requests.get(
            f"{_OTX_BASE}/indicators/domain/{domain}/general",
            headers=_HEADERS_OTX(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses      = pulse_info.get("pulses", [])

        tags: set[str] = set()
        families: set[str] = set()
        for p in pulses[:15]:
            tags.update(t.lower() for t in p.get("tags", []))
            if p.get("malware_families"):
                for mf in p["malware_families"]:
                    families.add(mf.get("display_name") or mf.get("id", ""))

        return {
            "status":          "found",
            "pulse_count":     pulse_count,
            "tags":            sorted(tags)[:8],
            "malware_families": sorted(families)[:5],
            "country":         data.get("country_name", ""),
            "asn":             data.get("asn", ""),
            "threat_level": (
                "malicious"  if pulse_count >= 5 else
                "suspicious" if pulse_count >= 1 else
                "clean"
            ),
            "report_url": f"https://otx.alienvault.com/indicator/domain/{domain}",
        }
    except requests.Timeout:
        return {"status": "timeout", "message": "OTX request timed out"}
    except Exception:
        return {"status": "error", "message": "OTX request failed"}


# ── PhishTank ──────────────────────────────────────────────────────────────────

def _check_phishtank(url: str) -> dict:
    try:
        payload: dict = {"url": url, "format": "json"}
        if settings.PHISHTANK_APP_KEY:
            payload["app_key"] = settings.PHISHTANK_APP_KEY

        resp = requests.post(
            _PT_URL,
            data=payload,
            headers={"User-Agent": "PhishGuard/2.0"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        r = resp.json().get("results", {})

        in_db    = bool(r.get("in_database"))
        verified = bool(r.get("verified"))

        return {
            "status":         "found" if in_db else "not_found",
            "in_database":    in_db,
            "verified":       verified,
            "phish_id":       r.get("phish_id"),
            "verified_at":    r.get("verified_at"),
            "report_url":     r.get("phish_detail_url"),
            "threat_level": (
                "malicious"  if in_db and verified else
                "suspicious" if in_db else
                "clean"
            ),
        }
    except requests.Timeout:
        return {"status": "timeout", "message": "PhishTank request timed out"}
    except Exception:
        return {"status": "error", "message": "PhishTank request failed"}


# ── Public entry point ──────────────────────────────────────────────────────────

def enrich_url(url: str) -> dict:
    """
    Query all configured OSINT feeds in parallel and return a combined result.
    Cached for _TTL seconds per URL.
    """
    now = time.monotonic()
    if url in _CACHE:
        cached_result, ts = _CACHE[url]
        if now - ts < _TTL:
            return {**cached_result, "cached": True}

    feeds = {
        "virustotal": _check_virustotal,
        "otx":        _check_otx,
        "phishtank":  _check_phishtank,
    }
    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=3) as pool:
        future_map = {pool.submit(fn, url): name for name, fn in feeds.items()}
        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                results[name] = fut.result()
            except Exception:
                results[name] = {"status": "error", "message": "Feed request failed"}

    # Overall threat level - worst of the three feeds
    levels = [r.get("threat_level", "clean") for r in results.values()]
    overall = (
        "malicious"  if "malicious"  in levels else
        "suspicious" if "suspicious" in levels else
        "clean"
    )

    # Any key configured?
    any_configured = any(
        r.get("status") not in ("unconfigured",)
        for r in results.values()
    )

    output: dict = {
        "url":                  url,
        "virustotal":           results.get("virustotal", {}),
        "otx":                  results.get("otx", {}),
        "phishtank":            results.get("phishtank", {}),
        "overall_threat_level": overall,
        "any_feed_configured":  any_configured,
        "enriched_at":          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cached":               False,
    }
    _CACHE[url] = (output, now)
    return output
