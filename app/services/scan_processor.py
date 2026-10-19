"""Pure scan logic - no HTTP concerns. Called by scan.py endpoints."""
import io
import json
import logging
import threading
import uuid
from typing import Optional

import numpy as np
from PIL import Image
import pytesseract

import app.services.ensemble_engine as engine
from app.services.risk_engine import compute_risk_score
from app.services.explainability import get_lime_explanation, generate_reasoning
from app.services.calibration import calibrate_confidence, get_confidence_interval
from app.services.qr_detector import detect_qr_codes
from app.services.audit_log import log_event
from app.services.url_reputation import get_tranco_rank, tranco_tier
from app.utils.url_features import extract_url_features
from app.utils.whois_helper import get_domain_age_days
from app.db.scan_records import save_scan
from app.core.config import settings
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── In-memory whitelist cache ─────────────────────────────────────────────────
# Loaded once at startup and invalidated by admin whitelist writes.
_whitelist: set[str] = set()
_whitelist_lock = threading.RLock()


def reload_whitelist() -> None:
    """Load (or re-load) the whitelist from disk into the in-memory cache."""
    global _whitelist
    # F-46: acquire lock before opening file to prevent torn reads during concurrent writes
    with _whitelist_lock:
        try:
            with open(settings.WHITELIST_FILE) as f:
                domains = set(json.load(f))
            _whitelist = domains
        except Exception as exc:
            logger.warning("Could not load whitelist file: %s", exc)


def get_whitelist_domains() -> set[str]:
    with _whitelist_lock:
        return set(_whitelist)


def process_email(text: str, explain: bool = True) -> dict:
    pred_label, confidence, all_probs, model_preds = engine.predict_email_ensemble(text)
    cal_conf = calibrate_confidence(confidence)
    conf_lo, conf_hi = get_confidence_interval(cal_conf)
    explanation = get_lime_explanation(text) if explain else None
    risk_info   = compute_risk_score(pred_label, cal_conf, text)
    reasoning   = generate_reasoning(pred_label, cal_conf, model_preds, explanation,
                                     text=text, risk_info=risk_info)
    return {
        "prediction": pred_label,
        "confidence": cal_conf,
        "confidence_interval": [conf_lo, conf_hi],
        "all_probabilities": all_probs,
        "model_predictions": model_preds,
        "explanation": explanation,
        "reasoning": reasoning,
        "risk_info": risk_info,
    }


def _is_whitelisted(domain: str, trusted: set) -> bool:
    """Return True if domain exactly matches or is a subdomain of any trusted domain."""
    if domain in trusted:
        return True
    for td in trusted:
        if domain.endswith('.' + td):
            return True
    return False


def process_url(url: str) -> dict:
    netloc = urlparse(url).netloc.lower()
    if ':' in netloc:
        netloc = netloc.rsplit(':', 1)[0]
    domain = netloc.removeprefix("www.")

    trusted = get_whitelist_domains()
    if not trusted:
        reload_whitelist()
        trusted = get_whitelist_domains()

    if _is_whitelisted(domain, trusted):
        label = "legitimate"
        risk_info = {"score": 0.0, "level": "Low"}
        breakdown = {"gradient_boosting": {"prediction": label, "confidence": 1.0, "weight": 1.0,
                                            "probabilities": {"legitimate": 1.0, "phishing": 0.0}}}
        reasoning = generate_reasoning(label, 1.0, breakdown, None, text=url, risk_info=risk_info)
        return {
            "prediction": label, "confidence": 1.0,
            "confidence_interval": [0.97, 1.0],
            "features": {},
            "all_probabilities": {"legitimate": 1.0, "phishing": 0.0},
            "model_predictions": breakdown,
            "reasoning": reasoning, "risk_info": risk_info,
            "whitelisted": True,
        }

    features = extract_url_features(url)
    age_days = get_domain_age_days(domain)
    features["domain_age_days"] = age_days if age_days is not None else 365

    phishing_prob, legit_prob, breakdown = engine.predict_url(url)

    # Derive label from ensemble probability
    if phishing_prob >= 0.75:
        label = "phishing"
    elif phishing_prob >= 0.45:
        label = "suspicious"
    else:
        label = "legitimate"
    confidence = phishing_prob if label != "legitimate" else legit_prob

    # Tranco reputation override: well-known domains that the ML model got wrong
    t_rank = get_tranco_rank(domain)
    t_tier = tranco_tier(t_rank)
    if t_tier == 1 and label in ("phishing", "suspicious"):
        label      = "legitimate"
        confidence = 0.90
    elif t_tier == 2 and label == "phishing":
        label = "suspicious"

    cal_conf = calibrate_confidence(confidence)
    conf_lo, conf_hi = get_confidence_interval(cal_conf)
    risk_info = compute_risk_score(label, cal_conf, url, url_features=features)
    reasoning = generate_reasoning(label, cal_conf, breakdown, None, text=url, risk_info=risk_info)
    if age_days is not None and age_days < 30:
        reasoning["risk_story"] = (
            f"Domain registered only {age_days} days ago. " + reasoning.get("risk_story", "")
        )

    return {
        "prediction": label, "confidence": round(cal_conf, 4),
        "confidence_interval": [conf_lo, conf_hi],
        "features": features,
        "all_probabilities": {"legitimate": round(legit_prob, 4),
                              "phishing":   round(phishing_prob, 4)},
        "model_predictions": breakdown,
        "reasoning": reasoning, "risk_info": risk_info,
        "whitelisted": False,
        "tranco_rank": t_rank,
        "tranco_tier": t_tier,
    }


_MAX_IMAGE_DIMENSION = 4096   # F-33: pixel-flood / decompression bomb protection


def process_image(image_bytes: bytes, explain: bool = True) -> dict:
    img = Image.open(io.BytesIO(image_bytes))
    if img.width > _MAX_IMAGE_DIMENSION or img.height > _MAX_IMAGE_DIMENSION:
        raise ValueError(
            f"Image dimensions {img.width}x{img.height} exceed the "
            f"{_MAX_IMAGE_DIMENSION}px limit."
        )
    img = img.convert("RGB")
    extracted = pytesseract.image_to_string(img).strip()
    if len(extracted) < 10:
        raise ValueError("No text found in image.")

    qr_result   = detect_qr_codes(image_bytes)
    pred_label, confidence, all_probs, model_preds = engine.predict_email_ensemble(extracted)
    cal_conf    = calibrate_confidence(confidence)
    conf_lo, conf_hi = get_confidence_interval(cal_conf)
    explanation = get_lime_explanation(extracted) if explain else None
    risk_info   = compute_risk_score(pred_label, cal_conf, extracted)
    reasoning   = generate_reasoning(pred_label, cal_conf, model_preds, explanation,
                                     text=extracted, risk_info=risk_info)
    return {
        "extracted_text": extracted, "char_count": len(extracted),
        "prediction": pred_label, "confidence": round(cal_conf, 4),
        "confidence_interval": [conf_lo, conf_hi],
        "all_probabilities": all_probs, "model_predictions": model_preds,
        "explanation": explanation, "reasoning": reasoning,
        "qr_detection": qr_result, "risk_info": risk_info,
    }


def persist_and_log(scan_id: str, scan_type: str, content: str,
                    result: dict, actor: str, extra: Optional[dict] = None) -> None:
    """Fire-and-forget save + audit log. Logs failures at WARNING level."""
    try:
        save_scan(scan_id, scan_type, content,
                  result["prediction"], result["confidence"],
                  result.get("model_predictions", {}),
                  result.get("reasoning", {}))
    except Exception:
        logger.warning("persist scan %s failed", scan_id, exc_info=True)
    try:
        log_event(f"scan.{scan_type}", actor, {
            "scan_id": scan_id,
            "prediction": result.get("prediction"),
            "confidence": round(float(result.get("confidence", 0)), 4),
            "risk_level": result.get("risk_info", {}).get("level"),
            **(extra or {}),
        })
    except Exception:
        logger.warning("audit log for scan %s failed", scan_id, exc_info=True)
