"""Versioned meta-learner retraining - called as a background task from admin.py.

Fast-loop retraining: retrain XGBoost meta-learner on validation data + confirmed
feedback corrections. Takes ~2 minutes, not hours. Hot-swaps the running model.
"""
import os
import shutil
import threading
import time

import numpy as np
import torch

_retrain_lock = threading.Lock()


def retrain_meta() -> None:
    """
    Retrain the XGBoost meta-learner on validation CSV + trusted user feedback.
    Hot-swaps the running model on success. Flagged / low-trust feedback excluded.
    Serialised by _retrain_lock to prevent concurrent retrains corrupting state.
    """
    if not _retrain_lock.acquire(blocking=False):
        print("[WARN]   Retrain already in progress - skipping duplicate request.")
        return
    try:
        _do_retrain()
    finally:
        _retrain_lock.release()


def _do_retrain() -> None:
    import pandas as pd
    import joblib
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    from sklearn.preprocessing import LabelEncoder
    from xgboost import XGBClassifier
    import app.services.ensemble_engine as engine
    from app.core.config import settings

    t0 = time.time()

    # ── Load validation data ──────────────────────────────────────────────────
    val_path = settings.VALIDATION_DATA
    base_texts, base_labels = [], []
    if os.path.exists(val_path):
        val_df = pd.read_csv(val_path)
        base_texts = val_df["clean_text"].fillna("").tolist()
        base_labels = val_df["label"].tolist()

    # ── Load confirmed feedback corrections ──────────────────────────────────
    feedback_texts, feedback_labels, feedback_weights = [], [], []
    try:
        from app.services.self_training_pipeline import get_confirmed_corrections
        corrections = get_confirmed_corrections()
        feedback_texts = [c["input_text"] for c in corrections]
        feedback_labels = [c["user_label"] for c in corrections]
        feedback_weights = [c["trust_score"] for c in corrections]
    except Exception as e:
        print(f"[WARN] Could not load feedback: {e}")

    all_texts = base_texts + feedback_texts
    all_labels = base_labels + feedback_labels
    all_weights = [1.0] * len(base_texts) + feedback_weights

    if len(all_texts) < 50:
        print("[WARN] Not enough data for retraining (need >= 50 samples).")
        return

    # ── Generate stacked predictions ─────────────────────────────────────────
    def _encode(text):
        tfidf_v = engine.tfidf.transform([text])
        lr_p = engine.lr_model.predict_proba(tfidf_v)[:, engine.REORDER_IDX][0]
        rf_p = engine.rf_model.predict_proba(tfidf_v)[:, engine.REORDER_IDX][0]
        db_enc = engine.deberta_tokenizer(text, padding="max_length", truncation=True,
                                          max_length=engine.MAX_LEN, return_tensors="pt")
        dr_enc = engine.distilroberta_tokenizer(text, padding="max_length", truncation=True,
                                                max_length=engine.MAX_LEN, return_tensors="pt")
        with torch.no_grad():
            db_p = torch.softmax(
                engine.deberta_model(db_enc["input_ids"].to(engine.DEVICE),
                                     db_enc["attention_mask"].to(engine.DEVICE)),
                dim=-1,
            ).cpu().numpy()[0]
            dr_p = torch.softmax(
                engine.distilroberta_model(dr_enc["input_ids"].to(engine.DEVICE),
                                           dr_enc["attention_mask"].to(engine.DEVICE)),
                dim=-1,
            ).cpu().numpy()[0]
        return np.concatenate([lr_p, rf_p, db_p, dr_p])

    X_rows, y_rows, w_rows = [], [], []
    le = LabelEncoder()
    y_all_encoded = le.fit_transform(all_labels)

    for text, label_enc, weight in zip(all_texts, y_all_encoded, all_weights):
        try:
            X_rows.append(_encode(text))
            y_rows.append(label_enc)
            w_rows.append(weight)
        except Exception:
            continue

    if len(X_rows) < 50:
        print("[WARN] Not enough encodable samples.")
        return

    X_all = np.array(X_rows)
    y_all = np.array(y_rows)
    w_all = np.array(w_rows)

    # ── Train/test split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test, w_train, _ = train_test_split(
        X_all, y_all, w_all, test_size=0.2, random_state=42, stratify=y_all
    )

    new_meta = XGBClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        eval_metric="mlogloss", random_state=42,
    )
    new_meta.fit(X_train, y_train, sample_weight=w_train)

    # ── Validate ──────────────────────────────────────────────────────────────
    y_pred = new_meta.predict(X_test)
    new_accuracy = accuracy_score(y_test, y_pred)

    version_file = os.path.join(settings.MODELS_DIR, "meta_version.txt")
    current_v = 1
    if os.path.exists(version_file):
        with open(version_file) as f:
            current_v = int(f.read().strip())
    old_path = os.path.join(settings.MODELS_DIR, f"meta_learner_v{current_v}.pkl")
    if os.path.exists(old_path):
        old_meta = joblib.load(old_path)
        y_pred_old = old_meta.predict(X_test)
        old_accuracy = accuracy_score(y_test, y_pred_old)
        if new_accuracy < old_accuracy * 0.98:
            print(f"[WARN] New model ({new_accuracy:.4f}) worse than old "
                  f"({old_accuracy:.4f}). Keeping old.")
            return

    # ── Save ──────────────────────────────────────────────────────────────────
    new_v = current_v + 1
    new_path = os.path.join(settings.MODELS_DIR, f"meta_learner_v{new_v}.pkl")
    joblib.dump(new_meta, new_path)

    tmp_version = version_file + ".tmp"
    with open(tmp_version, "w") as f:
        f.write(str(new_v))
    shutil.move(tmp_version, version_file)

    engine.meta_model = new_meta
    engine.use_meta_learner = True

    elapsed = time.time() - t0
    print(
        f"[OK]  Meta-learner v{new_v} trained in {elapsed:.1f}s. "
        f"Accuracy: {new_accuracy:.4f} ({len(base_texts)} base + "
        f"{len(feedback_texts)} feedback = {len(all_texts)} total)"
    )
