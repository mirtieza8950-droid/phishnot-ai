from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from app.core.dependencies import get_current_user, require_admin
from app.services.brand_protection import brand_dns_check, scan_lookalikes
from app.services.ct_logs import query_ct_logs
from app.services.audit_log import log_event
from app.services.phishing_kit_fingerprinter import fingerprint_url, PHISHING_KITS

router = APIRouter()

_lookalike_cache: dict[str, dict] = {}
_scanning: set[str] = set()


class DomainRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2000)


@router.post("/dmarc", dependencies=[Depends(get_current_user)])
def check_dmarc(req: DomainRequest):
    domain = req.domain.strip().lower().lstrip("www.")
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")
    result = brand_dns_check(domain)
    try:
        log_event("brand.dmarc_check", "api", {"domain": domain, "grade": result["grade"]})
    except Exception:
        pass
    return result


@router.post("/lookalikes/scan", dependencies=[Depends(require_admin)])  # F-29: admin only - launches 40-worker DNS probes
def start_lookalike_scan(req: DomainRequest, background_tasks: BackgroundTasks):
    domain = req.domain.strip().lower().lstrip("www.")
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")
    if domain in _scanning:
        return {"status": "running", "domain": domain}
    if domain in _lookalike_cache:
        return {"status": "cached", "domain": domain, "result": _lookalike_cache[domain]}

    _scanning.add(domain)

    def _run(d: str):
        try:
            result = scan_lookalikes(d)
            _lookalike_cache[d] = result
            log_event("brand.lookalike_scan", "api", {
                "domain": d,
                "generated": result["total_generated"],
                "registered": result["registered_count"],
            })
        except Exception as exc:
            _lookalike_cache[d] = {"error": str(exc)}
        finally:
            _scanning.discard(d)

    background_tasks.add_task(_run, domain)
    return {"status": "started", "domain": domain}


@router.get("/lookalikes/status/{domain}", dependencies=[Depends(get_current_user)])
def lookalike_status(domain: str):
    domain = domain.strip().lower()
    if domain in _scanning:
        return {"status": "running"}
    if domain in _lookalike_cache:
        return {"status": "done", "result": _lookalike_cache[domain]}
    return {"status": "not_started"}


@router.get("/lookalikes/preview/{domain}", dependencies=[Depends(get_current_user)])
def lookalike_preview(domain: str):
    from app.services.brand_protection import generate_lookalikes
    domain = domain.strip().lower().lstrip("www.")
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")
    candidates = generate_lookalikes(domain)
    return {"domain": domain, "count": len(candidates), "candidates": candidates}


@router.post("/kit/fingerprint", dependencies=[Depends(get_current_user)])  # F-16: require auth
def kit_fingerprint(req: UrlRequest):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = fingerprint_url(url)
    if "error" in result:
        raise HTTPException(400, result["error"])
    try:
        log_event("brand.kit_fingerprint", "api", {
            "url": url,
            "matched_kit": result.get("matched_kit"),
            "risk_score": result.get("risk_score"),
            "indicators": len(result.get("indicators", [])),
        })
    except Exception:
        pass
    return result


@router.get("/kit/signatures")  # public - only lists kit metadata, no server-side fetch
def kit_signatures():
    return {
        "count": len(PHISHING_KITS),
        "kits": [
            {
                "id":          kid,
                "description": info["description"],
                "category":    info["category"],
                "targets":     info["targets"],
                "first_seen":  info["first_seen"],
            }
            for kid, info in PHISHING_KITS.items()
        ],
    }


@router.get("/ct/{domain}", dependencies=[Depends(get_current_user)])   # F-29: require auth
def get_ct_logs(domain: str, max_results: int = Query(300, ge=1, le=500)):
    domain = domain.strip().lower().lstrip("www.")
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")
    result = query_ct_logs(domain, max_results)
    try:
        log_event("brand.ct_scan", "api", {
            "domain": domain,
            "total": result.get("total", 0),
            "error": result.get("error"),
        })
    except Exception:
        pass
    return result
