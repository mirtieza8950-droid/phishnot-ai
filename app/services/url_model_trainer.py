"""
URL phishing model retraining.

Loads data/url_training_data.csv, extracts the 20 lexical URL features
(pure computation - no network calls), trains a GradientBoostingClassifier,
versions and saves the model, then hot-swaps the running instance.
"""
import os
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timezone
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

import app.services.ensemble_engine as engine
from app.utils.url_features import extract_url_features, get_feature_names
from app.core.config import settings

DATA_DIR   = "datasets"
_FEATURE_NAMES = get_feature_names()  # locked-in order - must match training and inference

_lock  = Lock()
_state: dict = {
    "status": "idle",       # idle | running | done | error
    "started_at": None,
    "finished_at": None,
    "version": None,
    "total_samples": 0,
    "train_samples": 0,
    "test_accuracy": None,
    "phishing_precision": None,
    "legitimate_recall": None,
    "error": None,
}


def get_state() -> dict:
    with _lock:
        return dict(_state)


def _set(**kw):
    with _lock:
        _state.update(kw)


def _extract(url: str) -> list | None:
    try:
        f = extract_url_features(str(url))
        return [f.get(n, 0) for n in _FEATURE_NAMES]
    except Exception:
        return None


def retrain_url_model(data_path: str | None = None, max_workers: int = 32) -> dict:
    """
    Full retrain pipeline. Call from a background thread (blocking).
    Returns a summary dict on success; raises on failure.
    """
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score

    data_path = data_path or os.path.join(DATA_DIR, "url_training_data.csv")

    _set(
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None, version=None,
        total_samples=0, train_samples=0,
        test_accuracy=None, phishing_precision=None, legitimate_recall=None,
        error=None,
    )

    if not os.path.exists(data_path):
        err = f"Training data not found at {data_path}. Run data ingestion first."
        _set(status="error", error=err,
             finished_at=datetime.now(timezone.utc).isoformat())
        raise FileNotFoundError(err)

    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        err = "CSV must have 'url' and 'label' columns."
        _set(status="error", error=err,
             finished_at=datetime.now(timezone.utc).isoformat())
        raise ValueError(err)

    urls   = df["url"].tolist()
    labels = df["label"].tolist()

    # Parallel feature extraction - pure computation, no I/O
    X_rows, y_rows = [], []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_extract, u): lbl for u, lbl in zip(urls, labels)}
        for fut in as_completed(futures):
            vec = fut.result()
            if vec is not None:
                X_rows.append(vec)
                y_rows.append(int(futures[fut]))

    if len(X_rows) < 200:
        err = f"Too few valid samples after feature extraction: {len(X_rows)}"
        _set(status="error", error=err,
             finished_at=datetime.now(timezone.utc).isoformat())
        raise ValueError(err)

    X = np.array(X_rows)
    y = np.array(y_rows)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )

    model = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1,
        subsample=0.8, min_samples_split=10,
        n_iter_no_change=10, random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred          = model.predict(X_test)
    accuracy        = float(accuracy_score(y_test, y_pred))
    phish_precision = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    legit_recall    = float(recall_score(y_test, y_pred,    pos_label=0, zero_division=0))

    # ── Version + persist ────────────────────────────────────────────────────
    version_file = os.path.join(settings.MODELS_DIR, "url_model_version.txt")
    version = 1
    if os.path.exists(version_file):
        try:
            version = int(open(version_file).read().strip()) + 1
        except Exception:
            pass

    versioned = os.path.join(settings.MODELS_DIR, f"url_phishing_model_v{version}.pkl")
    joblib.dump(model, versioned)
    joblib.dump(model, settings.URL_MODEL_PATH)   # overwrite primary path

    with open(version_file, "w") as f:
        f.write(str(version))

    # ── Hot-swap ─────────────────────────────────────────────────────────────
    engine.url_model = model

    _set(
        status="done",
        finished_at=datetime.now(timezone.utc).isoformat(),
        version=version,
        total_samples=len(X_rows),
        train_samples=len(X_train),
        test_accuracy=round(accuracy, 4),
        phishing_precision=round(phish_precision, 4),
        legitimate_recall=round(legit_recall, 4),
        error=None,
    )
    print(
        f"[OK]  URL model v{version} - {len(X_train):,} train | "
        f"accuracy {accuracy:.3f} | phishing precision {phish_precision:.3f}"
    )
    return get_state()
