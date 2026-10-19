"""
SSRF protection - resolves the hostname and rejects private/reserved addresses.

DNS-rebinding mitigation: we return the resolved IP alongside the safety verdict
so callers can bind to that IP directly instead of re-resolving at request time.
"""
import ipaddress
import socket
from urllib.parse import urlparse


def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Return (True, '') for safe URLs, (False, reason) for SSRF-unsafe targets.

    The caller MUST unpack the tuple:
        safe, reason = is_safe_url(url)
        if not safe:
            raise HTTPException(400, reason)

    Do NOT test the return value directly - a non-empty tuple is always truthy.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Scheme '{parsed.scheme}' not allowed"
        host = parsed.hostname
        if not host:
            return False, "No hostname"
        # Resolve once and cache the result - the caller should use this IP
        # to prevent DNS rebinding (resolve at check time != resolve at request time)
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            return False, f"Target IP {ip} is not a public address"
        return True, ""
    except socket.gaierror:
        return False, "Hostname could not be resolved"
    except Exception as exc:
        return False, str(exc)


def resolve_safe_host(url: str) -> tuple[bool, str, str]:
    """
    Like is_safe_url but also returns the resolved IP.
    Use the returned IP for the actual HTTP connection to prevent DNS rebinding.

    Returns (safe, reason, resolved_ip).
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Scheme '{parsed.scheme}' not allowed", ""
        host = parsed.hostname
        if not host:
            return False, "No hostname", ""
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            return False, f"Target IP {ip} is not a public address", ""
        return True, "", ip
    except socket.gaierror:
        return False, "Hostname could not be resolved", ""
    except Exception as exc:
        return False, str(exc), ""
