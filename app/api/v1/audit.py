from fastapi import APIRouter, Depends, Query
from app.core.dependencies import require_admin
from app.services.audit_log import get_entries, verify_chain

router = APIRouter()


@router.get("/log", dependencies=[Depends(require_admin)])
def get_audit_log(limit: int = Query(100, ge=1, le=1000)):
    entries = get_entries(limit)
    return {"count": len(entries), "entries": entries}


@router.get("/verify", dependencies=[Depends(require_admin)])
def verify_audit_chain():
    return verify_chain()
