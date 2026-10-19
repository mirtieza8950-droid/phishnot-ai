import json
import re
import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, Query
from pydantic import BaseModel, Field
from app.core.config import settings
from app.core.dependencies import require_admin
from app.core.limiter import limiter
from app.db.feedback import get_feedback_conn, get_feedback_conn_exclusive
from app.db.user import list_users, set_user_role, set_user_disabled, VALID_ROLES
from app.services.trust_scoring import score_submission, get_trust_stats, _text_fingerprint
from app.services.audit_log import log_event
from app.services.system_health import get_health
from app.services.model_retrainer import retrain_meta
from app.services.self_training_pipeline import (
    get_pipeline_stats, run_full_pipeline, get_confirmed_corrections,
    inject_canary_feedback, update_consensus,
)

router = APIRouter()

# Strict hostname regex - labels of 1-63 alnum/hyphen chars, no leading/trailing hyphen
_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class WhitelistRequest(BaseModel):
    domain: str

class FeedbackRequest(BaseModel):
    scan_id: str
    user_label: str
    model_prediction: str
    input_text: str
    input_type: Optional[str] = "email"

class FeedbackReviewRequest(BaseModel):
    reason: str = ""

class LoginRequest(BaseModel):
    password: str

class RoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|end_user)$")


def _actor(req: Request) -> str:
    return req.client.host if req.client else "unknown"


# ── Admin auth - F-03: brute-force protection via rate limit ──────────────────

@router.post("/verify")
@limiter.limit("5/minute")
def verify_admin(request: Request, req: LoginRequest):
    # slowapi requires the starlette Request to be the first param named `request`
    if req.password != settings.ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid password")
    session_id = secrets.token_urlsafe(16)
    request.session["admin_verified"] = True
    request.session["session_id"] = session_id
    return {"ok": True}


# ── Whitelist ─────────────────────────────────────────────────────────────────

@router.get("/whitelist", dependencies=[Depends(require_admin)])
def get_whitelist():
    from app.services.scan_processor import get_whitelist_domains
    return {"domains": sorted(get_whitelist_domains())}


@router.post("/whitelist", dependencies=[Depends(require_admin)])
def add_to_whitelist(req: WhitelistRequest, http_request: Request):
    from app.services.scan_processor import reload_whitelist
    import shutil
    domain = req.domain.strip().lower().lstrip("www.")
    if not domain:
        raise HTTPException(400, "Domain required")
    # F-32: validate as a proper hostname before accepting
    if not _HOSTNAME_RE.match(domain):
        raise HTTPException(400, f"'{domain}' is not a valid hostname")
    with open(settings.WHITELIST_FILE) as f:
        domains = set(json.load(f))
    domains.add(domain)
    tmp = settings.WHITELIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(domains), f, indent=2)
    shutil.move(tmp, settings.WHITELIST_FILE)
    reload_whitelist()
    try:
        log_event("admin.whitelist_add", _actor(http_request), {"domain": domain})
    except Exception:
        pass
    return {"message": f"Added {domain}"}


@router.delete("/whitelist", dependencies=[Depends(require_admin)])
def remove_from_whitelist(domain: str, http_request: Request):
    from app.services.scan_processor import reload_whitelist
    import shutil
    domain = domain.strip().lower()
    with open(settings.WHITELIST_FILE) as f:
        domains = set(json.load(f))
    if domain not in domains:
        raise HTTPException(404, f"Domain {domain} not found")
    domains.remove(domain)
    tmp = settings.WHITELIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(domains), f, indent=2)
    shutil.move(tmp, settings.WHITELIST_FILE)
    reload_whitelist()
    try:
        log_event("admin.whitelist_remove", _actor(http_request), {"domain": domain})
    except Exception:
        pass
    return {"message": f"Removed {domain}"}


# ── Feedback ──────────────────────────────────────────────────────────────────

@router.post("/feedback", dependencies=[Depends(require_admin)])
def submit_feedback(fb: FeedbackRequest, http_request: Request):
    ip   = _actor(http_request)
    fp   = _text_fingerprint(fb.input_text)
    trust_score, is_flagged, flag_reason = score_submission(
        ip, fb.input_text, fb.user_label, fb.model_prediction
    )

    # Phase 4: quarantine decision
    from app.services.self_training_pipeline import should_quarantine
    quarantined, quarantine_reason = should_quarantine(
        fb.user_label, fb.model_prediction, 0.0, trust_score
    )

    with get_feedback_conn() as conn:
        conn.execute(
            """INSERT INTO feedback
               (scan_id, user_label, model_prediction, input_text, input_type,
                submitter_ip, trust_score, flagged, flag_reason, text_fingerprint,
                consensus_count, canary, quarantined, quarantine_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)""",
            (fb.scan_id, fb.user_label, fb.model_prediction, fb.input_text,
             fb.input_type, ip, trust_score, int(is_flagged), flag_reason, fp,
             int(quarantined), quarantine_reason),
        )
        conn.commit()

    # Phase 4: update consensus after new feedback
    try:
        update_consensus()
    except Exception:
        pass

    # Phase 1: maybe inject a canary sample
    try:
        inject_canary_feedback()
    except Exception:
        pass

    try:
        log_event("feedback.submit", ip, {
            "scan_id": fb.scan_id, "user_label": fb.user_label,
            "model_prediction": fb.model_prediction, "input_type": fb.input_type,
            "trust_score": trust_score, "flagged": is_flagged, "flag_reason": flag_reason,
            "quarantined": quarantined, "quarantine_reason": quarantine_reason,
        })
    except Exception:
        pass
    return {"message": "Feedback recorded", "trust_score": trust_score,
            "flagged": is_flagged, "flag_reason": flag_reason if is_flagged else None,
            "quarantined": quarantined, "quarantine_reason": quarantine_reason if quarantined else None}


@router.get("/feedback", dependencies=[Depends(require_admin)])
def get_feedback(limit: int = Query(50, ge=1, le=1000)):   # F-35: upper bound enforced
    with get_feedback_conn() as conn:
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        return conn.execute(
            "SELECT * FROM feedback ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()


# ── Trust stats ───────────────────────────────────────────────────────────────

@router.get("/trust", dependencies=[Depends(require_admin)])
def trust_overview():
    stats   = get_trust_stats()
    blocked = sum(1 for s in stats if s["status"] == "blocked")
    return {"summary": {"total_submitters": len(stats), "blocked_submitters": blocked},
            "submitters": stats}


# ── Retrain ───────────────────────────────────────────────────────────────────

@router.post("/retrain", dependencies=[Depends(require_admin)])
def trigger_retrain(background_tasks: BackgroundTasks, http_request: Request):
    try:
        log_event("admin.retrain_triggered", _actor(http_request), {})
    except Exception:
        pass
    background_tasks.add_task(retrain_meta)
    return {"message": "Retraining started in background. Flagged/untrusted feedback is excluded."}


# ── User management ───────────────────────────────────────────────────────────

@router.get("/users", dependencies=[Depends(require_admin)])
def get_users():
    return {"users": list_users()}


@router.patch("/users/{user_id}/role", dependencies=[Depends(require_admin)])
def update_user_role(user_id: str, req: RoleRequest, http_request: Request):
    updated = set_user_role(user_id, req.role)
    if not updated:
        raise HTTPException(404, "User not found")
    try:
        log_event("admin.user_role_change", _actor(http_request),
                  {"user_id": user_id, "new_role": req.role})
    except Exception:
        pass
    return {"user": updated}


@router.patch("/users/{user_id}/status", dependencies=[Depends(require_admin)])
def update_user_status(user_id: str, http_request: Request, disabled: bool = False):
    updated = set_user_disabled(user_id, disabled)
    if not updated:
        raise HTTPException(404, "User not found")
    action = "admin.user_disabled" if disabled else "admin.user_enabled"
    try:
        log_event(action, _actor(http_request), {"user_id": user_id})
    except Exception:
        pass
    return {"user": updated}


# ── Tranco reputation ─────────────────────────────────────────────────────────

@router.get("/tranco/status", dependencies=[Depends(require_admin)])
def tranco_status():
    from app.services.url_reputation import status as tranco_stat
    return tranco_stat()


@router.post("/tranco/refresh", dependencies=[Depends(require_admin)])
def tranco_refresh(http_request: Request):
    from app.services.url_reputation import refresh_tranco
    result = refresh_tranco()
    try:
        log_event("admin.tranco_refresh", _actor(http_request), result)
    except Exception:
        pass
    return result


# ── System health ─────────────────────────────────────────────────────────────

@router.get("/health", dependencies=[Depends(require_admin)])
def system_health():
    return get_health()


# ── Self-learning pipeline ────────────────────────────────────────────────────

@router.get("/feedback/quarantine", dependencies=[Depends(require_admin)])
def get_quarantine(limit: int = Query(50, ge=1, le=500)):
    """List quarantined feedback awaiting admin review."""
    with get_feedback_conn() as conn:
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        return conn.execute(
            "SELECT * FROM feedback WHERE quarantined = 1 ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()


@router.post("/feedback/{feedback_id}/approve", dependencies=[Depends(require_admin)])
def approve_feedback(feedback_id: int, http_request: Request):
    """Approve quarantined feedback — remove quarantine flag."""
    with get_feedback_conn_exclusive() as conn:
        conn.execute(
            "UPDATE feedback SET quarantined = 0, quarantine_reason = '' WHERE id = ?",
            (feedback_id,),
        )
        conn.commit()
    try:
        log_event("admin.feedback_approve", _actor(http_request), {"feedback_id": feedback_id})
    except Exception:
        pass
    return {"message": f"Feedback {feedback_id} approved"}


@router.post("/feedback/{feedback_id}/reject", dependencies=[Depends(require_admin)])
def reject_feedback(feedback_id: int, req: FeedbackReviewRequest, http_request: Request):
    """Reject quarantined feedback — flag it and penalize submitter trust."""
    with get_feedback_conn_exclusive() as conn:
        row = conn.execute(
            "SELECT submitter_ip FROM feedback WHERE id = ?", (feedback_id,)
        ).fetchone()
        if row:
            ip = row[0]
            conn.execute(
                "UPDATE feedback SET flagged = 1, flag_reason = ? WHERE id = ?",
                (f"admin_rejected: {req.reason}" if req.reason else "admin_rejected", feedback_id),
            )
            # Penalize trust
            conn.execute(
                "UPDATE feedback SET trust_score = MAX(0.0, trust_score - 0.15) "
                "WHERE submitter_ip = ?",
                (ip,),
            )
            conn.commit()
    try:
        log_event("admin.feedback_reject", _actor(http_request),
                  {"feedback_id": feedback_id, "reason": req.reason})
    except Exception:
        pass
    return {"message": f"Feedback {feedback_id} rejected"}


@router.get("/feedback/stats", dependencies=[Depends(require_admin)])
def feedback_stats():
    """Pipeline statistics — consensus, canaries, anomalies, training readiness."""
    return get_pipeline_stats()


@router.get("/feedback/confirmed", dependencies=[Depends(require_admin)])
def confirmed_corrections():
    """List corrections that passed all gates and are ready for training."""
    return {"corrections": get_confirmed_corrections()}


@router.post("/self-learning/run", dependencies=[Depends(require_admin)])
def trigger_self_learning(background_tasks: BackgroundTasks, http_request: Request):
    """Run the full self-learning pipeline in the background."""
    try:
        log_event("admin.self_learning_triggered", _actor(http_request), {})
    except Exception:
        pass
    background_tasks.add_task(_run_pipeline_background)
    return {"message": "Self-learning pipeline started in background"}


def _run_pipeline_background():
    """Background wrapper for the pipeline."""
    try:
        result = run_full_pipeline()
        print(f"[SELF-LEARNING] Pipeline complete: {result.get('training_data_count', 0)} "
              f"corrections ready, {result.get('canary_penalties_applied', 0)} penalties applied")
    except Exception as e:
        print(f"[SELF-LEARNING] Pipeline error: {e}")


@router.get("/self-learning/status", dependencies=[Depends(require_admin)])
def self_learning_status():
    """Scheduler status — next run times, last run times."""
    from app.services.self_learning_scheduler import get_scheduler
    return get_scheduler().status()


@router.post("/self-learning/run-now", dependencies=[Depends(require_admin)])
def trigger_meta_retrain(http_request: Request):
    """Manually trigger meta-learner retrain (fast loop, ~2 min)."""
    try:
        log_event("admin.meta_retrain_triggered", _actor(http_request), {})
    except Exception:
        pass
    background_tasks = BackgroundTasks()
    background_tasks.add_task(_do_meta_retrain_background)
    return {"message": "Meta-learner retrain started in background"}


def _do_meta_retrain_background():
    try:
        from app.services.model_retrainer import retrain_meta
        retrain_meta()
    except Exception as e:
        print(f"[RETRAIN] Error: {e}")


@router.post("/lora/finetune", dependencies=[Depends(require_admin)])
def trigger_lora_finetune(http_request: Request):
    """Manually trigger LoRA fine-tuning (monthly, ~30 min)."""
    try:
        log_event("admin.lora_finetune_triggered", _actor(http_request), {})
    except Exception:
        pass
    background_tasks = BackgroundTasks()
    background_tasks.add_task(_do_lora_finetune_background)
    return {"message": "LoRA fine-tuning started in background"}


def _do_lora_finetune_background():
    try:
        import subprocess, sys
        subprocess.run(
            [sys.executable, "train_lora_adapters.py", "--epochs", "2"],
            capture_output=True, text=True, timeout=3600,
        )
        from app.services.ensemble_engine import load_all_models
        load_all_models()
    except Exception as e:
        print(f"[LORA] Error: {e}")
