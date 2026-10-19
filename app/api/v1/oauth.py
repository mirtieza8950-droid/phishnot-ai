"""OAuth / token-theft detection endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.oauth_detector import analyze_url, analyze_email, KNOWN_PROVIDERS
from app.services.audit_log import log_event

router = APIRouter()


class UrlRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    text: str


@router.post("/analyze-url")
def detect_oauth_url(req: UrlRequest):
    """Analyze a URL for OAuth phishing, token exposure, and AiTM indicators."""
    url = req.url.strip()
    if not url:
        raise HTTPException(400, "URL required")
    result = analyze_url(url)
    try:
        log_event("oauth.url_analyzed", "api", {
            "url": url[:120],
            "risk_score": result["risk_score"],
            "threat_type": result.get("threat_type"),
        })
    except Exception:
        pass
    return result


@router.post("/analyze-email")
def detect_oauth_email(req: EmailRequest):
    """Scan email body text for OAuth consent-phishing and embedded token URLs."""
    if not req.text.strip():
        raise HTTPException(400, "Email text required")
    result = analyze_email(req.text)
    try:
        log_event("oauth.email_analyzed", "api", {
            "urls_found": result["urls_found"],
            "risk_score": result["overall_risk_score"],
        })
    except Exception:
        pass
    return result


@router.get("/providers")
def list_providers():
    """Return the list of known legitimate OAuth provider domains."""
    return {
        "count": len(KNOWN_PROVIDERS),
        "providers": [
            {"host": host, "name": info["name"]}
            for host, info in KNOWN_PROVIDERS.items()
        ],
    }
