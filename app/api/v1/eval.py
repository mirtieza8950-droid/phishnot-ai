from fastapi import APIRouter, BackgroundTasks, Depends, Query, HTTPException
from app.core.dependencies import require_admin
from app.services.red_team_eval import run_evaluation, load_results, is_running
from app.services.audit_log import log_event

router = APIRouter()


@router.post("/run", dependencies=[Depends(require_admin)])
def trigger_evaluation(
    background_tasks: BackgroundTasks,
    max_samples: int = Query(default=500, ge=10, le=5000),
):
    if is_running():
        raise HTTPException(409, "Evaluation already in progress")
    try:
        log_event("admin.eval_triggered", "api", {"max_samples": max_samples})
    except Exception:
        pass
    background_tasks.add_task(run_evaluation, max_samples)
    return {"message": f"Evaluation started on up to {max_samples} samples", "status": "running"}


@router.get("/status", dependencies=[Depends(require_admin)])
def eval_status():
    return {"running": is_running()}


@router.get("/results", dependencies=[Depends(require_admin)])
def get_eval_results():
    results = load_results()
    if results is None:
        return {"results": None, "message": "No evaluation has been run yet"}
    return {"results": results}
