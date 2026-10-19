"""
URL Feature Extraction for Phishing Detection.

Extracts lexical, statistical, and structural features from URLs
to classify them as phishing or legitimate.
"""

import re
import math
from urllib.parse import urlparse


# Known suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.work', '.buzz', '.surf', '.fit', '.link', '.click', '.zip'
}

# Known shortening services
SHORTENING_SERVICES = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'short.io'
}


def entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in prob.values())


def extract_url_features(url):
    """
    Extract 20 features from a URL for phishing detection.
    Returns a dict of feature_name -> value.
    """
    features = {}

    # Ensure URL has scheme for proper parsing
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = 'http://' + url
    else:
        url_with_scheme = url

    parsed = urlparse(url_with_scheme)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # 1. URL length
    features['url_length'] = len(url)

    # 2. Hostname length
    features['hostname_length'] = len(hostname)

    # 3. Path length
    features['path_length'] = len(path)

    # 4. Number of dots in URL
    features['num_dots'] = url.count('.')

    # 5. Number of hyphens in hostname
    features['num_hyphens'] = hostname.count('-')

    # 6. Number of underscores
    features['num_underscores'] = url.count('_')

    # 7. Number of slashes in path
    features['num_slashes'] = path.count('/')

    # 8. Number of query parameters
    features['num_params'] = len(query.split('&')) if query else 0

    # 9. Has IP address as hostname
    features['has_ip'] = int(bool(re.match(
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname
    )))

    # 10. Has @ symbol (used to trick users)
    features['has_at_symbol'] = int('@' in url)

    # 11. Has double slash redirect (after protocol)
    features['has_double_slash_redirect'] = int('//' in url[8:])

    # 12. Uses HTTPS
    features['is_https'] = int(parsed.scheme == 'https')

    # 13. Number of subdomains
    subdomain_parts = hostname.split('.')
    features['num_subdomains'] = max(0, len(subdomain_parts) - 2)

    # 14. Has suspicious TLD
    features['suspicious_tld'] = int(
        any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    )

    # 15. Is URL shortened
    features['is_shortened'] = int(
        any(svc in hostname for svc in SHORTENING_SERVICES)
    )

    # 16. Number of digits in URL
    features['num_digits'] = sum(c.isdigit() for c in url)

    # 17. Number of special characters
    features['num_special_chars'] = sum(
        not c.isalnum() and c not in './-:?' for c in url
    )

    # 18. URL entropy (randomness indicator)
    features['url_entropy'] = round(entropy(url), 4)

    # 19. Has suspicious keywords in URL
    suspicious_keywords = [
        'login', 'signin', 'verify', 'secure', 'account', 'update',
        'confirm', 'banking', 'password', 'credential', 'suspended',
        'unusual', 'alert', 'paypal', 'apple', 'microsoft', 'amazon'
    ]
    url_lower = url.lower()
    features['num_suspicious_keywords'] = sum(
        1 for kw in suspicious_keywords if kw in url_lower
    )

    # 20. Ratio of digits to total length
    features['digit_ratio'] = round(features['num_digits'] / max(len(url), 1), 4)

    return features


def get_feature_names():
    """Return ordered list of feature names."""
    return [
        'url_length', 'hostname_length', 'path_length', 'num_dots',
        'num_hyphens', 'num_underscores', 'num_slashes', 'num_params',
        'has_ip', 'has_at_symbol', 'has_double_slash_redirect', 'is_https',
        'num_subdomains', 'suspicious_tld', 'is_shortened', 'num_digits',
        'num_special_chars', 'url_entropy', 'num_suspicious_keywords',
        'digit_ratio'
    ]
