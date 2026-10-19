import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from app.core.dependencies import require_admin
from app.core.limiter import limiter
from app.services.browser_sandbox import sandbox_scan_sync
from app.services.audit_log import log_event

router = APIRouter()

_jobs: dict[str, dict] = {}


class SandboxRequest(BaseModel):
    url: str = Field(..., min_length=7, max_length=2000)


def _run_job(job_id: str, url: str) -> None:
    try:
        result = sandbox_scan_sync(url)
    except Exception as exc:
        result = {"url": url, "error": str(exc), "risk_score": 0, "risk_level": "Error", "findings": []}
    result["status"] = "done" if "error" not in result else "error"
    _jobs[job_id] = result
    try:
        log_event("sandbox.scan", "api", {
            "url": url[:120],
            "risk_score": result.get("risk_score"),
            "error": result.get("error"),
        })
    except Exception:
        pass


# F-17: admin-only + tight rate limit - headless Chromium is resource-intensive
@router.post("/scan", dependencies=[Depends(require_admin)])
@limiter.limit("2/minute")
async def start_sandbox_scan(request: Request, req: SandboxRequest, background_tasks: BackgroundTasks):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    from app.utils.ssrf_guard import is_safe_url
    safe, reason = is_safe_url(url)
    if not safe:
        raise HTTPException(400, f"URL blocked: {reason}")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "running", "url": url, "started_at": datetime.now(timezone.utc).isoformat()}
    background_tasks.add_task(_run_job, job_id, url)
    return {"job_id": job_id, "status": "running"}


@router.get("/status/{job_id}", dependencies=[Depends(require_admin)])
def sandbox_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {"status": job.get("status", "running"), "error": job.get("error")}


@router.get("/result/{job_id}", dependencies=[Depends(require_admin)])
def sandbox_result(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("status") == "running":
        raise HTTPException(202, "Scan still running")
    return job
