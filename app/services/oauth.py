"""
OAuth service - handles token exchange with Google & Microsoft.
"""
import requests
from app.core.config import settings

GOOGLE_DISCOVERY = "https://accounts.google.com/.well-known/openid-configuration"
MICROSOFT_DISCOVERY = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"

def _discover(provider: str) -> dict:
    url = GOOGLE_DISCOVERY if provider == "google" else MICROSOFT_DISCOVERY
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()

def get_authorization_url(provider: str, redirect_uri: str, state: str) -> str:
    cfg = _discover(provider)
    if provider == "google":
        client_id = settings.GOOGLE_CLIENT_ID
        scope = "openid email profile"
    else:
        client_id = settings.MICROSOFT_CLIENT_ID
        scope = "openid email profile"
    return (
        f"{cfg['authorization_endpoint']}?"
        f"response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&"
        f"scope={scope}&state={state}"
    )

def exchange_code(provider: str, code: str, redirect_uri: str) -> dict:
    cfg = _discover(provider)
    if provider == "google":
        client_id = settings.GOOGLE_CLIENT_ID
        client_secret = settings.GOOGLE_CLIENT_SECRET
    else:
        client_id = settings.MICROSOFT_CLIENT_ID
        client_secret = settings.MICROSOFT_CLIENT_SECRET

    resp = requests.post(cfg["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()
    # Fetch user info
    userinfo = requests.get(cfg["userinfo_endpoint"], headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, timeout=10).json()
    return {
        "email": userinfo["email"],
        "name": userinfo.get("name", userinfo.get("email", "").split("@")[0]),
        "provider": provider,
    }