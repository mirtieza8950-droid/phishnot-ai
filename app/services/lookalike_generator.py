"""Lookalike / typosquatting domain generation and registration probing."""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

_KEYBOARD_ADJ: dict[str, str] = {
    "a": "sqzw", "b": "vghn", "c": "xdfv", "d": "ersfxc", "e": "rdsw",
    "f": "rtgdvc", "g": "tyhfvb", "h": "yugjbn", "i": "uojk", "j": "uihknm",
    "k": "iolj", "l": "opk", "m": "njk", "n": "bhjm", "o": "ipkl",
    "p": "ol", "q": "wa", "r": "etfd", "s": "wedxza", "t": "yrfg",
    "u": "yihjk", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "utrg",
    "z": "asx",
}
_DOMAIN_HOMOGL: dict[str, list[str]] = {
    "m": ["rn", "nn"], "n": ["ri"], "l": ["1", "i"],
    "o": ["0"], "i": ["l", "1"], "a": ["4"],
    "e": ["3"], "g": ["q"], "rn": ["m"],
}
_PHISH_SUFFIXES = ["-login", "-secure", "-verify", "-account", "-update",
                   "-signin", "-support", "login", "secure", "verify"]
_PHISH_PREFIXES = ["my", "secure", "login", "account", "signin", "support"]
_EXTRA_TLDS     = [".net", ".org", ".co", ".info", ".biz", ".io",
                   ".online", ".site", ".live", ".xyz", ".app"]


def _has_a_record(domain: str) -> bool:
    try:
        socket.setdefaulttimeout(3)
        return len(socket.getaddrinfo(domain, None)) > 0
    except Exception:
        return False


def generate_lookalikes(domain: str) -> list[str]:
    domain = domain.strip().lower()
    if "." not in domain:
        return []
    parts = domain.rsplit(".", 1)
    label, tld = parts[0], "." + parts[1]
    candidates: set[str] = set()

    for i in range(len(label)):
        candidates.add(label[:i] + label[i+1:] + tld)
        candidates.add(label[:i] + label[i] * 2 + label[i+1:] + tld)
        if i < len(label) - 1:
            s = list(label); s[i], s[i+1] = s[i+1], s[i]
            candidates.add("".join(s) + tld)
        for adj in _KEYBOARD_ADJ.get(label[i], ""):
            candidates.add(label[:i] + adj + label[i+1:] + tld)

    for orig, reps in _DOMAIN_HOMOGL.items():
        if orig in label:
            for rep in reps:
                candidates.add(label.replace(orig, rep, 1) + tld)

    for alt in _EXTRA_TLDS:
        if alt != tld:
            candidates.add(label + alt)

    candidates.add(label.replace("-", "") + tld)
    for i in range(1, len(label)):
        candidates.add(label[:i] + "-" + label[i:] + tld)

    for suf in _PHISH_SUFFIXES:
        candidates.add(label + suf + tld)
    for pre in _PHISH_PREFIXES:
        candidates.add(pre + label + tld)
        candidates.add(pre + "-" + label + tld)

    candidates.add("www" + label + tld)
    candidates.discard(domain)
    candidates.discard(label + tld)
    candidates = {c for c in candidates if 3 <= len(c) <= 63 and c.replace("-", "").replace(".", "").isalnum()}
    return sorted(candidates)


def scan_lookalikes(domain: str, max_workers: int = 10) -> dict:  # F-38: reduced from 40
    candidates = generate_lookalikes(domain)
    registered, unregistered = [], []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(_has_a_record, d): d for d in candidates}
        for fut in as_completed(future_map):
            d = future_map[fut]
            try:
                (registered if fut.result() else unregistered).append(d)
            except Exception:
                unregistered.append(d)
    registered.sort()
    unregistered.sort()
    return {
        "seed_domain": domain,
        "total_generated": len(candidates),
        "registered_count": len(registered),
        "registered": registered,
        "unregistered_sample": unregistered[:50],
    }
