import asyncio
import io
import json
import sqlite3
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import torch

from app.core.limiter import limiter
from app.core.dependencies import get_current_user, require_admin
from app.services.scan_processor import process_email, process_url, process_image, persist_and_log
import app.services.ai_chat as _ai_chat
from app.services.ai_chat import ask_llm_about_scan, build_scan_context
from app.services.report_generator import generate_forensic_report_pdf
from app.services.vision_forensics import analyze_screenshot, vision_model, vision_processor
from app.services.header_forensics import parse_email_headers
from app.services.qr_detector import detect_qr_codes
from app.services.redirect_tracer import trace_redirects
from app.services.prompt_firewall import detect_injection, sanitize
from app.db.scan_records import save_scan
from app.core.config import settings

router = APIRouter()

# ── Image upload constraints (F-11) ──────────────────────────────────────────
_MAX_IMAGE_BYTES = 10 * 1024 * 1024   # 10 MB
_IMAGE_MAGIC: dict[bytes, str] = {
    b"\xff\xd8\xff":  "jpeg",
    b"\x89PNG\r\n":   "png",
    b"GIF8":          "gif",
    b"RIFF":          "webp",   # RIFF....WEBP
    b"BM":            "bmp",
}


def _validate_image(data: bytes) -> None:
    if len(data) > _MAX_IMAGE_BYTES:
        raise HTTPException(413, f"Image too large - maximum {_MAX_IMAGE_BYTES // 1024 // 1024} MB")
    for magic, fmt in _IMAGE_MAGIC.items():
        if data[:len(magic)] == magic:
            return
    raise HTTPException(415, "Unsupported image format - send JPEG, PNG, GIF, WebP, or BMP")


# ── Request models ─────────────────────────────────────────────────────────────

class EmailRequest(BaseModel):
    text: str
    explain: bool = True

class URLRequest(BaseModel):
    url: str

class AskRequest(BaseModel):
    prediction: str
    confidence: float
    model_predictions: dict
    explanation: Optional[list] = None
    reasoning: Optional[dict] = None
    text: Optional[str] = None
    question: str

class ReportRequest(BaseModel):
    prediction: str
    confidence: float
    model_predictions: dict
    reasoning: Optional[dict] = None
    scan_id: str = ""

class VisualRequest(BaseModel):
    image_base64: str
    url_hint: Optional[str] = None

class ThinkingRequest(BaseModel):
    text: str
    prediction: Optional[str] = None

class HeaderRequest(BaseModel):
    raw_headers: str

class TraceRequest(BaseModel):
    url: str
    max_hops: int = Field(default=12, ge=1, le=20)


def _actor(http_req: Request) -> str:
    return http_req.client.host if http_req.client else "unknown"


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/email", dependencies=[Depends(get_current_user)])
def scan_email(http_req: Request, request: EmailRequest):
    result  = process_email(request.text, request.explain)
    scan_id = str(uuid.uuid4())
    persist_and_log(scan_id, "email", request.text, result, _actor(http_req))
    return {**result, "scan_id": scan_id, "warning": None}


@router.post("/url", dependencies=[Depends(get_current_user)])
def scan_url(http_req: Request, request: URLRequest):
    result  = process_url(request.url)
    scan_id = str(uuid.uuid4())
    persist_and_log(scan_id, "url", request.url, result, _actor(http_req),
                    extra={"url": request.url, "whitelisted": result.get("whitelisted", False)})
    return {"url": request.url, **result, "scan_id": scan_id, "warning": None}


@router.post("/image", dependencies=[Depends(get_current_user)])
async def scan_image(http_req: Request, file: UploadFile = File(...), explain: bool = Query(True)):
    image_bytes = await file.read()
    _validate_image(image_bytes)          # F-11: size + magic-byte check
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, process_image, image_bytes, explain)
    except ValueError as e:
        raise HTTPException(422, str(e))
    scan_id = str(uuid.uuid4())
    persist_and_log(scan_id, "image", result["extracted_text"], result, _actor(http_req),
                    extra={"qr_codes_found": len(result.get("qr_detection", {}).get("codes", []))})
    return {**result, "scan_id": scan_id, "warning": None}


@router.post("/ask", dependencies=[Depends(get_current_user)])
@limiter.limit("20/minute")
def ask_analyst(request: Request, body: AskRequest):
    if detect_injection(body.question):
        return {"question": body.question, "answer": "I cannot process that request due to security concerns."}
    risk_info = None
    if body.reasoning:
        risk_info = {"score": body.reasoning.get("risk_score"),
                     "level": body.reasoning.get("risk_level")}
    context = build_scan_context(body.prediction, body.confidence, body.model_predictions,
                                 body.explanation, risk_info, body.text or "")
    return {"question": body.question, "answer": ask_llm_about_scan(context, body.question)}


@router.post("/thinking", dependencies=[Depends(get_current_user)])
@limiter.limit("10/minute")
def ai_thinking(request: Request, body: ThinkingRequest):
    if detect_injection(body.text):
        return {"thinking": "Security check: this content contains suspicious patterns."}
    safe_text = sanitize(body.text, max_length=1500)
    # User content is placed inside explicit delimiters so the model cannot
    # interpret it as instructions (F-23 prompt injection mitigation)
    prompt = (
        "You are a cybersecurity expert. Analyze the content below (delimited by <email>) "
        "step-by-step for phishing indicators. Look for: urgency cues, credential requests, "
        "suspicious links, grammar anomalies, sender impersonation. "
        "Format your response as numbered points. Be concise (under 200 words).\n\n"
        f"<email>\n{safe_text}\n</email>"
    )
    if body.prediction:
        prompt += f"\n\nThe ensemble classifier predicts: {body.prediction}."

    try:
        if vision_model is not None and vision_processor is not None:
            messages = [{"role": "user", "content": prompt}]
            text = vision_processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = vision_processor(text=[text], images=None, return_tensors="pt").to(vision_model.device)
            with torch.no_grad():
                generated_ids = vision_model.generate(**inputs, max_new_tokens=280, temperature=0.35)
            trimmed = [out[len(inp):] for inp, out in zip(inputs.input_ids, generated_ids)]
            return {"thinking": vision_processor.batch_decode(trimmed, skip_special_tokens=True)[0].strip()}
    except Exception as e:
        print(f"Local model thinking failed: {e}")

    if not _ai_chat.ai_client or not _ai_chat.AI_MODEL:
        return {"thinking": "AI analysis unavailable - set GROQ_API_KEY, OPENROUTER_API_KEY, or GOOGLE_API_KEY in .env to enable it."}
    try:
        response = _ai_chat.ai_client.chat.completions.create(
            model=_ai_chat.AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=280, temperature=0.35,
        )
        return {"thinking": response.choices[0].message.content}
    except Exception:
        return {"thinking": "Could not generate step-by-step reasoning."}


@router.post("/visual", dependencies=[Depends(get_current_user)])
@limiter.limit("5/minute")        # F-09: GPU-exhaustion protection
def visual_forensics(request: Request, body: VisualRequest):
    return {"analysis": analyze_screenshot(body.image_base64)}


@router.post("/headers", dependencies=[Depends(get_current_user)])
def scan_headers(request: HeaderRequest):
    return parse_email_headers(request.raw_headers)


@router.post("/qr", dependencies=[Depends(get_current_user)])
async def scan_qr(http_req: Request, file: UploadFile = File(...)):
    data = await file.read()
    _validate_image(data)               # F-11: same check for QR uploads
    return detect_qr_codes(data)


@router.post("/trace", dependencies=[Depends(get_current_user)])
def trace_url(request: TraceRequest):
    from urllib.parse import urlparse as _up
    from app.utils.ssrf_guard import is_safe_url
    parsed = _up(request.url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "Only http and https URLs are supported for tracing")
    safe, reason = is_safe_url(request.url)     # F-18: was `if not is_safe_url(...)` - tuple always truthy
    if not safe:
        raise HTTPException(400, f"URL blocked: {reason}")
    return trace_redirects(request.url, max_hops=request.max_hops)


@router.post("/report/pdf", dependencies=[Depends(get_current_user)])   # F-24
def download_report_pdf(request: ReportRequest):
    path = generate_forensic_report_pdf(request.dict())
    # F-25: generate_forensic_report_pdf now returns a tempfile path; delete after send
    return FileResponse(path, media_type="application/pdf",
                        filename=f"phishguard_report_{request.scan_id or 'scan'}.pdf",
                        background=None)


@router.get("/report/{scan_id}", dependencies=[Depends(get_current_user)])  # F-24
def download_past_report(scan_id: str):
    from app.db._helpers import abs_db_path, db_conn
    import sqlite3 as _sqlite3
    with db_conn(abs_db_path("phishguard.db")) as conn:
        conn.row_factory = _sqlite3.Row
        row = conn.execute("SELECT * FROM scan_records WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found.")
    scan_data = {
        "prediction":       row["prediction"],
        "confidence":       row["confidence"],
        "model_predictions": json.loads(row["model_breakdown"]) if row["model_breakdown"] else {},
        "reasoning":        json.loads(row["reasoning"]) if row["reasoning"] else {},
        "scan_id":          scan_id,
    }
    path = generate_forensic_report_pdf(scan_data)
    return FileResponse(path, media_type="application/pdf",
                        filename=f"phishguard_report_{scan_id}.pdf")
