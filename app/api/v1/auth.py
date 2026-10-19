"""Authentication endpoints - OAuth login, callback, me, logout."""
import uuid
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from app.services.oauth import get_authorization_url, exchange_code
from app.db.user import get_user_by_email, create_user, get_user_by_id
from app.core.config import settings
from app.core.dependencies import get_current_user, require_admin
from app.services.audit_log import log_event

router = APIRouter()

_ALLOWED_PROVIDERS = {"google", "microsoft"}


@router.get("/login/{provider}")
async def login(provider: str, request: Request):
    if provider not in _ALLOWED_PROVIDERS:
        raise HTTPException(400, "Provider must be 'google' or 'microsoft'")
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"]    = state
    request.session["oauth_provider"] = provider   # F-21: bind provider to state
    redirect_uri = f"{settings.OAUTH_REDIRECT_URI}/{provider}/callback"
    url = get_authorization_url(provider, redirect_uri, state)
    return RedirectResponse(url)


@router.get("/{provider}/callback")
async def callback(provider: str, code: str, state: str, request: Request):
    if provider not in _ALLOWED_PROVIDERS:
        raise HTTPException(400, "Invalid provider")
    if state != request.session.get("oauth_state"):
        raise HTTPException(400, "State mismatch")
    # F-21: verify provider matches the one that initiated the login flow
    expected_provider = request.session.get("oauth_provider")
    if expected_provider and provider != expected_provider:
        raise HTTPException(400, "Provider mismatch - possible substitution attack")

    redirect_uri = f"{settings.OAUTH_REDIRECT_URI}/{provider}/callback"
    info = exchange_code(provider, code, redirect_uri)
    user = get_user_by_email(info["email"])
    if not user:
        user = create_user(info["email"], info["name"], info["provider"])

    # Clear the OAuth state from session to prevent reuse
    request.session.pop("oauth_state", None)
    request.session.pop("oauth_provider", None)
    request.session["user_id"]    = user["id"]
    request.session["session_id"] = secrets.token_urlsafe(16)

    try:
        actor = request.client.host if request.client else "unknown"
        log_event("auth.login", actor, {"email": info["email"], "provider": provider})
    except Exception:
        pass
    return RedirectResponse("/")


@router.get("/me")
def me(current_user=Depends(get_current_user)):
    return current_user


@router.post("/logout")
async def logout(request: Request):
    from app.core.dependencies import revoke_session
    session_id = request.session.get("session_id")
    if session_id:
        revoke_session(session_id)
    try:
        actor = request.client.host if request.client else "unknown"
        log_event("auth.logout", actor, {})
    except Exception:
        pass
    request.session.clear()
    return {"ok": True}


@router.get("/admin-only")
def admin_only(current_user=Depends(require_admin)):
    return {"message": f"Welcome admin {current_user['name']}!"}
