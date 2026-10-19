"""Training data management and URL model retraining endpoints."""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from app.core.dependencies import require_admin
from app.services.data_ingestion import run_ingestion, get_state as get_ingest_state
from app.services.url_model_trainer import retrain_url_model, get_state as get_train_state
from app.services.audit_log import log_event

router = APIRouter()


class IngestRequest(BaseModel):
    use_phishing_db: bool = True
    use_kaggle: bool = True
    max_phishing_db: int = Field(20_000, ge=100, le=100_000)
    max_kaggle: int = Field(100_000, ge=100, le=500_000)


def _actor(req: Request) -> str:
    return req.client.host if req.client else "unknown"


@router.post("/ingest", dependencies=[Depends(require_admin)])
def trigger_ingest(body: IngestRequest, background_tasks: BackgroundTasks, http_req: Request):
    state = get_ingest_state()
    if state["status"] == "running":
        raise HTTPException(409, "Ingestion already running")

    def _run():
        try:
            run_ingestion(
                use_phishing_db=body.use_phishing_db,
                use_kaggle=body.use_kaggle,
                max_phishing_db=body.max_phishing_db,
                max_kaggle=body.max_kaggle,
            )
        except Exception as exc:
            print(f"[ingest] Background task error: {exc}")

    background_tasks.add_task(_run)
    try:
        log_event("training.ingest_triggered", _actor(http_req), {
            "use_phishing_db": body.use_phishing_db,
            "use_kaggle": body.use_kaggle,
        })
    except Exception:
        pass
    return {"message": "Ingestion started", "status": "running"}


@router.get("/ingest/status", dependencies=[Depends(require_admin)])
def ingest_status():
    return get_ingest_state()


@router.post("/url-model/retrain", dependencies=[Depends(require_admin)])
def trigger_url_retrain(background_tasks: BackgroundTasks, http_req: Request):
    ingest = get_ingest_state()
    if ingest["status"] != "done" or not ingest.get("data_path"):
        raise HTTPException(400, "No training data available - run data ingestion first")

    train = get_train_state()
    if train["status"] == "running":
        raise HTTPException(409, "URL model retraining already in progress")

    def _run():
        try:
            retrain_url_model(ingest["data_path"])
        except Exception as exc:
            print(f"[url_retrain] Error: {exc}")

    background_tasks.add_task(_run)
    try:
        log_event("training.url_retrain_triggered", _actor(http_req), {
            "data_path": ingest.get("data_path"),
            "total_urls": ingest.get("total"),
        })
    except Exception:
        pass
    return {"message": "URL model retraining started"}


@router.get("/url-model/status", dependencies=[Depends(require_admin)])
def url_model_status():
    return get_train_state()
