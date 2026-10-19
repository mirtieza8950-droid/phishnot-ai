"""Mobile phishing detection endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.mobile_phishing import analyze_sms, analyze_deeplink, analyze_mobile_url
from app.services.audit_log import log_event

router = APIRouter()


class SmsRequest(BaseModel):
    text: str

class LinkRequest(BaseModel):
    link: str

class UrlRequest(BaseModel):
    url: str


@router.post("/analyze-sms")
def detect_smishing(req: SmsRequest):
    if not req.text.strip():
        raise HTTPException(400, "SMS text required")
    result = analyze_sms(req.text)
    try:
        log_event("mobile.sms_analyzed", "api", {
            "risk_score": result["risk_score"],
            "threat_type": result.get("threat_type"),
            "brand": result["indicators"].get("impersonated_brand"),
        })
    except Exception:
        pass
    return result


@router.post("/analyze-deeplink")
def detect_deeplink(req: LinkRequest):
    if not req.link.strip():
        raise HTTPException(400, "Deep link required")
    result = analyze_deeplink(req.link)
    try:
        log_event("mobile.deeplink_analyzed", "api", {
            "scheme": result.get("scheme"),
            "risk_score": result["risk_score"],
            "threat_type": result.get("threat_type"),
        })
    except Exception:
        pass
    return result


@router.post("/analyze-url")
def detect_mobile_url(req: UrlRequest):
    if not req.url.strip():
        raise HTTPException(400, "URL required")
    result = analyze_mobile_url(req.url)
    try:
        log_event("mobile.url_analyzed", "api", {
            "risk_score": result["risk_score"],
            "threat_type": result.get("threat_type"),
        })
    except Exception:
        pass
    return result
