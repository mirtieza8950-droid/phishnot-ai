"""
FastAPI dependencies - authentication, admin guard, session revocation.

Production note (F-22): _revoked_sessions is in-process memory.
In a multi-worker or multi-instance deployment, replace with Redis:
    import redis; _redis = redis.Redis(); _redis.sadd("revoked", sid)
"""
import threading
from fastapi import HTTPException, Request, Depends
from app.db.user import get_user_by_id

_revoked_sessions: set[str] = set()
_revoked_lock = threading.Lock()


def revoke_session(session_id: str) -> None:
    with _revoked_lock:
        _revoked_sessions.add(session_id)


def _is_revoked(session_id: str) -> bool:
    with _revoked_lock:
        return session_id in _revoked_sessions


def get_current_user(request: Request) -> dict:
    # Admin password-based session
    if request.session.get("admin_verified"):
        session_id = request.session.get("session_id")
        # F-20: reject admin sessions that have no session_id (legacy or tampered)
        if not session_id:
            raise HTTPException(401, "Invalid session - please log in again.")
        if _is_revoked(session_id):
            raise HTTPException(401, "Session has been revoked. Please log in again.")
        return {
            "id":       "admin",
            "name":     "Admin",
            "email":    "admin@phishnot.local",
            "role":     "admin",
            "disabled": False,
        }

    # OAuth session
    user_id    = request.session.get("user_id")
    session_id = request.session.get("session_id")

    if not user_id:
        raise HTTPException(401, "Not authenticated")

    # F-20: also require session_id for OAuth users
    if not session_id:
        raise HTTPException(401, "Invalid session - please log in again.")

    if _is_revoked(session_id):
        raise HTTPException(401, "Session has been revoked. Please log in again.")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(401, "User not found")

    if user.get("disabled"):
        raise HTTPException(403, "Account is disabled")

    return user


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return current_user
