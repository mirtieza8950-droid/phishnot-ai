import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from app.core.dependencies import require_admin
from app.services.adversarial_gen import (
    generate_variants, export_to_csv, STRATEGY_NAMES, AdversarialVariant
)
from app.services.audit_log import log_event

router = APIRouter()

ADVERSARIAL_CSV = "adversarial_generated.csv"


class GenerateRequest(BaseModel):
    text:            str        = Field(..., min_length=10, max_length=5000)
    true_label:      str        = Field(..., pattern="^(phishing|spam|ham)$")
    strategies:      list[str]  = Field(default_factory=lambda: STRATEGY_NAMES)
    n_per_strategy:  int        = Field(default=3, ge=1, le=10)
    seed:            int        = Field(default=42)


class ExportRequest(BaseModel):
    variants:    list[dict]
    true_label:  str = Field(..., pattern="^(phishing|spam|ham)$")


# /strategies is intentionally public - it only lists algorithm names
@router.get("/strategies")
def list_strategies():
    return {"strategies": STRATEGY_NAMES}


@router.post("/generate", dependencies=[Depends(require_admin)])
def generate_adversarial(req: GenerateRequest):
    unknown = [s for s in req.strategies if s not in STRATEGY_NAMES]
    if unknown:
        raise HTTPException(400, f"Unknown strategies: {unknown}")

    variants = generate_variants(
        text=req.text,
        true_label=req.true_label,
        strategies=req.strategies,
        n_per_strategy=req.n_per_strategy,
        seed=req.seed,
    )

    fooled = sum(1 for v in variants if v.fooled)
    try:
        log_event("adversarial.generate", "api", {
            "true_label": req.true_label,
            "strategies": req.strategies,
            "total": len(variants),
            "fooled": fooled,
        })
    except Exception:
        pass

    return {
        "total":     len(variants),
        "fooled":    fooled,
        "fool_rate": round(fooled / len(variants), 4) if variants else 0.0,
        "variants": [
            {
                "strategy":   v.strategy,
                "text":       v.text,
                "prediction": v.prediction,
                "confidence": v.confidence,
                "fooled":     v.fooled,
            }
            for v in variants
        ],
    }


@router.post("/export", dependencies=[Depends(require_admin)])
def export_variants(req: ExportRequest):
    variants = [
        AdversarialVariant(
            strategy=v.get("strategy", ""),
            text=v.get("text", ""),
            prediction=v.get("prediction", ""),
            confidence=v.get("confidence", 0.0),
            fooled=v.get("fooled", False),
        )
        for v in req.variants
        if v.get("text")
    ]
    if not variants:
        raise HTTPException(400, "No valid variants provided")

    count = export_to_csv(variants, req.true_label, ADVERSARIAL_CSV)
    try:
        log_event("adversarial.export", "api", {
            "true_label": req.true_label, "rows_written": count,
        })
    except Exception:
        pass
    return {"message": f"Exported {count} variants to {ADVERSARIAL_CSV}", "rows": count}


@router.get("/download", dependencies=[Depends(require_admin)])
def download_csv():
    if not os.path.exists(ADVERSARIAL_CSV):
        raise HTTPException(404, "No adversarial CSV generated yet")
    return FileResponse(
        ADVERSARIAL_CSV,
        media_type="text/csv",
        filename="adversarial_generated.csv",
    )


@router.get("/stats", dependencies=[Depends(require_admin)])
def csv_stats():
    if not os.path.exists(ADVERSARIAL_CSV):
        return {"rows": 0, "labels": {}}
    import csv
    counts: dict[str, int] = {}
    total = 0
    with open(ADVERSARIAL_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get("label", "unknown")
            counts[lbl] = counts.get(lbl, 0) + 1
            total += 1
    return {"rows": total, "labels": counts}
