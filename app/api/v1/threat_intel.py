"""Threat intelligence enrichment endpoint."""
from fastapi import APIRouter, Depends, HTTPException, Query
from app.core.dependencies import get_current_user
from app.services.threat_intel import enrich_url
from app.services.audit_log import log_event

router = APIRouter()


@router.get("/lookup", dependencies=[Depends(get_current_user)])   # F-30: require auth
def lookup(url: str = Query(..., min_length=4, max_length=2000)):
    """Enrich a URL with VirusTotal, AlienVault OTX, and PhishTank data."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = enrich_url(url)
    try:
        log_event("threat_intel.lookup", "api", {
            "url": url[:120],
            "overall": result.get("overall_threat_level"),
            "cached": result.get("cached"),
            "vt_malicious": result.get("virustotal", {}).get("malicious"),
            "otx_pulses": result.get("otx", {}).get("pulse_count"),
            "phishtank": result.get("phishtank", {}).get("status"),
        })
    except Exception:
        pass
    return result
