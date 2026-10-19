"""
Red Team Evaluation Suite.

Runs the full ensemble (and each sub-model individually) against the validation
dataset to produce per-category precision, recall, F1, a confusion matrix, and
a ranked list of high-confidence misclassifications.

Results are stored to EVAL_RESULTS_PATH so they persist across restarts.
A threading lock prevents concurrent runs; callers can check _eval_running.
"""

import json, os, threading, numpy as np
from datetime import datetime, timezone

_eval_lock = threading.Lock()
_eval_running = False


def is_running() -> bool:
    return _eval_running


def _metrics(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict:
    """Return per-class and macro precision/recall/F1 without sklearn dependency on labels."""
    from sklearn.metrics import precision_recall_fscore_support, accuracy_score, confusion_matrix

    p, r, f, s = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    per_class = {
        lbl: {
            "precision": round(float(p[i]), 4),
            "recall":    round(float(r[i]), 4),
            "f1":        round(float(f[i]), 4),
            "support":   int(s[i]),
        }
        for i, lbl in enumerate(labels)
    }
    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    return {
        "accuracy":  round(float(accuracy_score(y_true, y_pred)), 4),
        "per_class": per_class,
        "macro_avg": {
            "precision": round(float(np.mean(p)), 4),
            "recall":    round(float(np.mean(r)), 4),
            "f1":        round(float(np.mean(f)), 4),
        },
        "confusion_matrix": {"labels": labels, "matrix": cm},
    }


def run_evaluation(max_samples: int | None = None) -> dict:
    """
    Run the Red Team evaluation suite.

    Args:
        max_samples: cap on how many rows to evaluate (None = all).
                     Defaults to settings.EVAL_MAX_SAMPLES if not provided.

    Returns the results dict (also saves it to EVAL_RESULTS_PATH).
    """
    global _eval_running

    if not _eval_lock.acquire(blocking=False):
        return {"error": "Evaluation already running"}

    _eval_running = True
    try:
        return _do_eval(max_samples)
    finally:
        _eval_running = False
        _eval_lock.release()


def _do_eval(max_samples: int | None) -> dict:
    import pandas as pd
    import torch
    import app.services.ensemble_engine as engine
    from app.core.config import settings

    cap = max_samples if max_samples is not None else settings.EVAL_MAX_SAMPLES

    val_path = settings.VALIDATION_DATA
    if not os.path.exists(val_path):
        return {"error": f"Validation data not found at {val_path}"}

    df = pd.read_csv(val_path)
    df = df[df["label"].isin(engine.LABEL_MAP)].reset_index(drop=True)
    if df.empty:
        return {"error": "No valid labeled samples in validation data"}

    if cap and len(df) > cap:
        df = df.sample(cap, random_state=42).reset_index(drop=True)

    texts  = df["clean_text"].fillna("").tolist()
    y_true = df["label"].tolist()
    labels = sorted(engine.LABEL_MAP.keys())  # consistent order

    # ── Collect predictions from each model ──────────────────────────
    ens_preds, lr_preds, rf_preds, db_preds, dr_preds = [], [], [], [], []
    ens_confs = []
    misclassified: list[dict] = []

    for i, text in enumerate(texts):
        tfidf_x = engine.tfidf.transform([text])
        lr_p  = engine.lr_model.predict_proba(tfidf_x)[:, engine.REORDER_IDX][0]
        rf_p  = engine.rf_model.predict_proba(tfidf_x)[:, engine.REORDER_IDX][0]

        db_enc = engine.deberta_tokenizer(
            text, padding="max_length", truncation=True,
            max_length=engine.MAX_LEN, return_tensors="pt"
        )
        dr_enc = engine.distilroberta_tokenizer(
            text, padding="max_length", truncation=True,
            max_length=engine.MAX_LEN, return_tensors="pt"
        )

        with torch.no_grad():
            db_p = torch.softmax(
                engine.deberta_model(db_enc["input_ids"].to(engine.DEVICE),
                                     db_enc["attention_mask"].to(engine.DEVICE)),
                dim=-1).cpu().numpy()[0]
            dr_p = torch.softmax(
                engine.distilroberta_model(dr_enc["input_ids"].to(engine.DEVICE),
                                           dr_enc["attention_mask"].to(engine.DEVICE)),
                dim=-1).cpu().numpy()[0]

        lr_preds.append(engine.LABEL_MAP_REVERSE[int(np.argmax(lr_p))])
        rf_preds.append(engine.LABEL_MAP_REVERSE[int(np.argmax(rf_p))])
        db_preds.append(engine.LABEL_MAP_REVERSE[int(np.argmax(db_p))])
        dr_preds.append(engine.LABEL_MAP_REVERSE[int(np.argmax(dr_p))])

        w_lr = engine.WEIGHTS.get("lr",            0.10)
        w_rf = engine.WEIGHTS.get("rf",            0.15)
        w_db = engine.WEIGHTS.get("deberta",       0.40)
        w_dr = engine.WEIGHTS.get("distilroberta", 0.35)

        if engine.use_meta_learner and engine.meta_model is not None:
            stacked = np.concatenate([lr_p, rf_p, db_p, dr_p]).reshape(1, -1)
            try:
                fp = engine.meta_model.predict_proba(stacked)[0]
                ep = np.zeros(3)
                for j, cls in enumerate(engine.meta_model.classes_):
                    ep[cls] = fp[j]
            except Exception:
                ep = w_lr * lr_p + w_rf * rf_p + w_db * db_p + w_dr * dr_p
        else:
            ep = w_lr * lr_p + w_rf * rf_p + w_db * db_p + w_dr * dr_p

        pred_idx  = int(np.argmax(ep))
        ens_label = engine.LABEL_MAP_REVERSE[pred_idx]
        ens_conf  = float(ep[pred_idx])

        ens_preds.append(ens_label)
        ens_confs.append(ens_conf)

        if ens_label != y_true[i] and ens_conf >= 0.70:
            misclassified.append({
                "true": y_true[i],
                "pred": ens_label,
                "confidence": round(ens_conf, 4),
                "text_preview": text[:120],
            })

    # Sort misclassified by confidence descending (worst offenders first)
    misclassified.sort(key=lambda x: x["confidence"], reverse=True)

    results = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "total_samples":  len(texts),
        "meta_learner":   engine.use_meta_learner,
        "ensemble":       _metrics(y_true, ens_preds, labels),
        "sub_models": {
            "logistic_regression": _metrics(y_true, lr_preds,  labels),
            "random_forest":       _metrics(y_true, rf_preds,  labels),
            "deberta":             _metrics(y_true, db_preds,  labels),
            "distilroberta":       _metrics(y_true, dr_preds,  labels),
        },
        "high_confidence_errors": misclassified[:20],
    }

    with open(settings.EVAL_RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


def load_results() -> dict | None:
    """Load the most recent saved results, or None if none exist."""
    from app.core.config import settings
    path = settings.EVAL_RESULTS_PATH
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
