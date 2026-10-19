"""
Tamper-evident audit logging via SHA-256 hash chain.

Each entry stores the hash of all previous entries (prev_hash) plus its own
content, forming a chain. Any modification to a past entry breaks the chain
and is detected by verify_chain().

Storage: append-only JSONL file - one JSON object per line.
"""

import hashlib, json, os, threading
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64
_lock = threading.Lock()
_entry_count: int | None = None  # lazy-initialized, incremented under _lock


def _log_path() -> str:
    from app.core.config import settings
    return settings.AUDIT_LOG_PATH


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _last_hash(path: str) -> str:
    """Return the entry_hash of the last line in the log file."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return GENESIS_HASH
    try:
        with open(path, "rb") as f:
            # Walk backwards past any trailing newlines to the last data byte
            f.seek(0, 2)
            pos = f.tell() - 1
            while pos >= 0:
                f.seek(pos)
                if f.read(1) not in (b"\n", b"\r"):
                    break
                pos -= 1
            # Walk backwards to find start of last line
            while pos > 0:
                f.seek(pos - 1)
                if f.read(1) == b"\n":
                    break
                pos -= 1
            f.seek(max(0, pos))
            line = f.read().strip()
        entry = json.loads(line)
        return entry.get("entry_hash", GENESIS_HASH)
    except Exception:
        return GENESIS_HASH


def _next_id(path: str) -> int:
    """Return the next sequential entry ID (must be called under _lock)."""
    global _entry_count
    if _entry_count is None:
        if os.path.exists(path):
            with open(path) as f:
                _entry_count = sum(1 for ln in f if ln.strip())
        else:
            _entry_count = 0
    _entry_count += 1
    return _entry_count


def log_event(event_type: str, actor: str, details: dict) -> None:
    """
    Append a tamper-evident entry to the audit log.

    Args:
        event_type: category string, e.g. "scan.email", "admin.whitelist_add"
        actor:      IP address or user identifier performing the action
        details:    arbitrary dict with event-specific context
    """
    with _lock:
        path = _log_path()
        prev_hash = _last_hash(path)
        entry_id = _next_id(path)
        timestamp = datetime.now(timezone.utc).isoformat()

        body = {
            "id": entry_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "details": details,
            "prev_hash": prev_hash,
        }
        # Hash is computed over the canonically-serialized body (no entry_hash field yet)
        body_str = json.dumps(body, sort_keys=True, separators=(",", ":"))
        body["entry_hash"] = _sha256(prev_hash + body_str)

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(body) + "\n")


def _redact_ip(ip: str) -> str:
    """F-41: mask last octet of IPv4 (or last group of IPv6) for privacy compliance."""
    if not ip or ip == "unknown":
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    # IPv6 - mask last group
    parts6 = ip.split(":")
    if len(parts6) > 1:
        return ":".join(parts6[:-1]) + ":xxxx"
    return ip


def get_entries(limit: int = 100) -> list[dict]:
    """Return up to `limit` entries, newest first."""
    path = _log_path()
    if not os.path.exists(path):
        return []
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
    except Exception:
        pass
    entries.reverse()
    # Redact actor IPs before returning to API callers
    for e in entries:
        if "actor" in e:
            e["actor"] = _redact_ip(e["actor"])
    return entries[:limit]


def verify_chain() -> dict:
    """
    Walk every entry and verify the hash chain is unbroken.

    Returns a dict with:
        valid (bool)
        checked (int)       - number of entries verified
        first_broken_id     - ID of first bad entry, or None
        reason (str | None) - human-readable failure description
    """
    path = _log_path()
    if not os.path.exists(path):
        return {"valid": True, "checked": 0, "first_broken_id": None, "reason": None}

    prev_hash = GENESIS_HASH
    checked = 0
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                entry = json.loads(raw)
                stored_hash = entry.get("entry_hash")

                if entry.get("prev_hash") != prev_hash:
                    return {
                        "valid": False,
                        "checked": checked,
                        "first_broken_id": entry.get("id"),
                        "reason": "prev_hash mismatch - entries may have been reordered or deleted",
                    }

                # Recompute hash from body without entry_hash
                body = {k: v for k, v in entry.items() if k != "entry_hash"}
                body_str = json.dumps(body, sort_keys=True, separators=(",", ":"))
                expected = _sha256(prev_hash + body_str)

                if stored_hash != expected:
                    return {
                        "valid": False,
                        "checked": checked,
                        "first_broken_id": entry.get("id"),
                        "reason": f"entry_hash mismatch at id={entry.get('id')} - content was modified",
                    }

                prev_hash = stored_hash
                checked += 1

    except Exception as exc:
        return {"valid": False, "checked": checked, "first_broken_id": None, "reason": str(exc)}

    return {"valid": True, "checked": checked, "first_broken_id": None, "reason": None}
