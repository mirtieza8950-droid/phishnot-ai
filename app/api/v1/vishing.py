"""Vishing analysis endpoints - job-based because transcription takes 10-30 s."""
import os
import uuid
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, UploadFile, File, HTTPException

from app.services.vishing_analyzer import analyze_audio
from app.services.audit_log import log_event

router = APIRouter()

_jobs: dict[str, dict] = {}

_MAX_BYTES   = 25 * 1024 * 1024   # 25 MB (Whisper API limit)
_ALLOWED_EXT = {".wav", ".mp3", ".m4a", ".ogg", ".flac", ".webm", ".mp4", ".aac", ".opus"}


def _run_job(job_id: str, audio_path: str) -> None:
    """Sync background worker - Starlette runs this in its thread pool."""
    try:
        result = analyze_audio(audio_path)
        _jobs[job_id] = {
            "status":      "done",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            **result,
        }
        try:
            log_event("vishing.analyzed", "api", {
                "job_id":           job_id,
                "risk_score":       result.get("risk_score"),
                "threat_type":      result.get("threat_type"),
                "transcript_length": result.get("transcript_length"),
            })
        except Exception:
            pass
    except Exception as exc:
        _jobs[job_id] = {
            "status":      "error",
            "error":       str(exc),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        try:
            os.unlink(audio_path)
        except Exception:
            pass


@router.post("/analyze")
async def analyze_vishing(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Upload an audio file (WAV / MP3 / M4A / OGG / FLAC / WEBM / MP4 ≤ 25 MB).
    Returns a job_id to poll with GET /vishing/status/{job_id}.
    """
    content = await file.read()
    if len(content) > _MAX_BYTES:
        raise HTTPException(413, "File too large - maximum 25 MB")

    # F-12: strip path separators from user-controlled filename before using it
    safe_name = Path(file.filename or "audio.wav").name if file.filename else "audio.wav"
    suffix = Path(safe_name).suffix.lower() or ".wav"
    if suffix not in _ALLOWED_EXT:
        raise HTTPException(415, f"Unsupported format '{suffix}'. Accepted: {', '.join(sorted(_ALLOWED_EXT))}")

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status":     "processing",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "filename":   safe_name,
        "size_bytes": len(content),
    }
    background_tasks.add_task(_run_job, job_id, tmp_path)
    return {"job_id": job_id, "status": "processing"}


@router.get("/status/{job_id}")
def vishing_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {"status": job.get("status"), "error": job.get("error"), "filename": job.get("filename")}


@router.get("/result/{job_id}")
def vishing_result(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("status") == "processing":
        raise HTTPException(202, "Transcription still running - poll /status first")
    return job
