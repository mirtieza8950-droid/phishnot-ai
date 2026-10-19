from fastapi import APIRouter, Depends, Query
from app.core.dependencies import require_admin
from app.db.scan_records import get_scans, get_analytics

router = APIRouter()


@router.get("/", dependencies=[Depends(require_admin)])
def list_history(limit: int = Query(50, ge=1, le=200)):
    return get_scans(limit)


@router.get("/analytics", dependencies=[Depends(require_admin)])
def analytics_summary():
    return get_analytics()
