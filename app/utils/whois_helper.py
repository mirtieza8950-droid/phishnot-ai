import concurrent.futures
import whois
from datetime import datetime, timedelta, timezone
from typing import Optional

_whois_cache: dict[str, tuple[Optional[int], datetime]] = {}
_WHOIS_TIMEOUT = 8   # F-37: hard timeout so a slow WHOIS server can't block a worker thread


def _do_whois(domain: str) -> Optional[int]:
    now = datetime.now(timezone.utc)
    w = whois.whois(domain)
    creation_date = w.creation_date
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        # Make aware if naive
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        return (now - creation_date).days
    return None


def get_domain_age_days(domain: str) -> Optional[int]:
    domain = domain.lower().strip()
    now = datetime.now(timezone.utc)

    if domain in _whois_cache:
        age, timestamp = _whois_cache[domain]
        if now - timestamp < timedelta(hours=1):
            return age

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_whois, domain)
            age = future.result(timeout=_WHOIS_TIMEOUT)
    except (concurrent.futures.TimeoutError, Exception):
        age = None

    _whois_cache[domain] = (age, now)
    return age
