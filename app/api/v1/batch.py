from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException

import numpy as np
import app.services.ensemble_engine as engine
from app.core.dependencies import get_current_user
from app.services.risk_engine import compute_risk_score
from app.utils.url_features import extract_url_features, get_feature_names

router = APIRouter()

MAX_BATCH_SIZE = 500


@router.post("/", dependencies=[Depends(get_current_user)])   # F-26: require auth
async def batch_scan(items: List[Dict[str, Any]]):
    if len(items) > MAX_BATCH_SIZE:
        raise HTTPException(
            413,
            f"Batch too large: {len(items)} items. Maximum is {MAX_BATCH_SIZE}.",
        )

    results = []
    for idx, item in enumerate(items):
        try:
            if "text" in item:
                pred_label, confidence, _, model_preds = engine.predict_email_ensemble(item["text"])
                risk_info = compute_risk_score(pred_label, confidence, item["text"])
                results.append({
                    "index": idx, "type": "email",
                    "prediction": pred_label, "confidence": round(confidence, 4),
                    "risk_score": risk_info["score"], "risk_level": risk_info["level"],
                    "scan_id": "",
                })
            elif "url" in item:
                if engine.url_model is None:
                    results.append({"index": idx, "error": "URL model not loaded"})
                    continue
                features = extract_url_features(item["url"])
                X = np.array([[features[f] for f in get_feature_names()]])
                pred = int(engine.url_model.predict(X)[0])
                proba = engine.url_model.predict_proba(X)[0]
                label = "phishing" if pred == 1 else "legitimate"
                confidence = float(proba[pred])
                if label == "phishing" and confidence < 0.85:
                    label = "suspicious"
                risk_info = compute_risk_score(label, confidence, item["url"], url_features=features)
                results.append({
                    "index": idx, "type": "url",
                    "prediction": label, "confidence": round(confidence, 4),
                    "risk_score": risk_info["score"], "risk_level": risk_info["level"],
                    "scan_id": "",
                })
            else:
                results.append({"index": idx, "error": "item must have 'text' or 'url'"})
        except Exception as e:
            results.append({"index": idx, "error": str(e)})
    return {"total": len(items), "results": results}
