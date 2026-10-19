"""Phase 3 - Confidence calibration via temperature scaling."""
import numpy as np


TEMPERATURE = 1.4  # tuned on validation set; >1 = softer, <1 = sharper


def calibrate_probs(raw_probs: dict, temperature: float = TEMPERATURE) -> dict:
    """Apply temperature scaling to a label->probability dict."""
    labels = list(raw_probs.keys())
    logits = np.log(np.clip([raw_probs[l] for l in labels], 1e-9, 1 - 1e-9))
    scaled = logits / temperature
    exp = np.exp(scaled - scaled.max())
    probs = exp / exp.sum()
    return {l: round(float(p), 4) for l, p in zip(labels, probs)}


def calibrate_confidence(confidence: float, temperature: float = TEMPERATURE) -> float:
    """Calibrate a scalar confidence value."""
    # log-odds scaling
    logit = np.log(np.clip(confidence, 1e-9, 1 - 1e-9))
    scaled_logit = logit / temperature
    calibrated = float(1 / (1 + np.exp(-scaled_logit)))
    return round(calibrated, 4)


def get_confidence_interval(confidence: float) -> tuple:
    """Approximate 90% confidence interval around a calibrated score."""
    margin = max(0.03, 0.18 * (1.0 - confidence))
    lo = round(max(0.0, confidence - margin), 4)
    hi = round(min(1.0, confidence + margin), 4)
    return (lo, hi)
