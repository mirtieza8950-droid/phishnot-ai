"""
Domain reputation via the Tranco top-sites list.

Tranco aggregates multiple ranking sources (Alexa, Umbrella, Majestic, Quantcast)
into a single, manipulation-resistant list updated weekly.

How it is used here:
  - Tier 1  (rank ≤ 10 000): extremely well-known domain - override phishing/suspicious -> legitimate
  - Tier 2  (rank ≤ 100 000): well-known domain - downgrade phishing -> suspicious
  - Not ranked: no adjustment - ML verdict stands

The service is an *enhancement*, not a hard dependency. If the list cannot be
downloaded or loaded, get_tranco_rank() returns None and scanning is unaffected.
"""

import csv
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

TRANCO_URL = "https://tranco-list.eu/download/latest/100000"
CACHE_FILE = Path("data/tranco_top100k.csv")
CACHE_MAX_AGE_DAYS = 7

TIER1_THRESHOLD = 10_000
TIER2_THRESHOLD = 100_000

# In-memory dict: domain -> rank (populated by init_tranco)
_tranco: dict[str, int] = {}


# ── Domain normalisation ───────────────────────────────────────────────────────

def _root_domain(domain: str) -> str:
    """
    Best-effort extraction of the registrable domain (eTLD+1).

    Handles common two-label ccSLDs (.co.uk, .com.au, .org.uk ...) by checking
    whether the penultimate label is a short pseudo-TLD (≤ 3 chars).
    """
    parts = domain.rstrip('.').split('.')
    if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


# ── Cache management ───────────────────────────────────────────────────────────

def _cache_is_fresh() -> bool:
    if not CACHE_FILE.exists():
        return False
    age_seconds = time.time() - CACHE_FILE.stat().st_mtime
    return age_seconds < CACHE_MAX_AGE_DAYS * 86_400


def _download() -> bool:
    """Download the Tranco list to CACHE_FILE. Returns True on success."""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading Tranco top-100k list from %s ...", TRANCO_URL)
        req = urllib.request.Request(
            TRANCO_URL,
            headers={"User-Agent": "PhishGuard-URL-Reputation/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("Tranco list saved to %s", CACHE_FILE)
        return True
    except Exception as exc:
        logger.warning("Tranco download failed (%s). Reputation checks disabled until next retry.", exc)
        return False


def _load() -> None:
    """Parse CACHE_FILE and populate _tranco dict."""
    global _tranco
    _tranco = {}
    if not CACHE_FILE.exists():
        return
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    try:
                        rank = int(row[0])
                        domain = row[1].lower().strip()
                        _tranco[domain] = rank
                    except (ValueError, IndexError):
                        continue
        logger.info("Tranco list loaded: %d domains.", len(_tranco))
    except Exception as exc:
        logger.warning("Could not load Tranco cache: %s", exc)
        _tranco = {}


# ── Public API ─────────────────────────────────────────────────────────────────

def init_tranco() -> None:
    """
    Called once at startup (in a background thread so it does not delay boot).
    Downloads the list if stale, then loads it into memory.
    """
    if not _cache_is_fresh():
        _download()
    _load()


def get_tranco_rank(domain: str) -> Optional[int]:
    """
    Return Tranco rank for *domain* (1 = most popular).
    Checks the exact domain first, then its registrable root.
    Returns None if the domain is not in the list or the list has not loaded.
    """
    if not _tranco:
        return None
    domain = domain.lower().strip()
    rank = _tranco.get(domain)
    if rank is not None:
        return rank
    return _tranco.get(_root_domain(domain))


def tranco_tier(rank: Optional[int]) -> Optional[int]:
    """Return 1, 2, or None based on rank thresholds."""
    if rank is None:
        return None
    if rank <= TIER1_THRESHOLD:
        return 1
    if rank <= TIER2_THRESHOLD:
        return 2
    return None


def refresh_tranco() -> dict:
    """Force re-download and reload. Called from the admin endpoint."""
    ok = _download()
    if ok:
        _load()
    return {"success": ok, "domains_loaded": len(_tranco)}


def status() -> dict:
    return {
        "domains_loaded": len(_tranco),
        "cache_file": str(CACHE_FILE),
        "cache_fresh": _cache_is_fresh(),
        "tier1_threshold": TIER1_THRESHOLD,
        "tier2_threshold": TIER2_THRESHOLD,
    }
