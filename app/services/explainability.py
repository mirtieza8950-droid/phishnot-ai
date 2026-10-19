"""
Explainability service - LIME & reasoning.
"""
import app.services.ensemble_engine as engine
from lime.lime_text import LimeTextExplainer

# Lazy‑loaded LIME explainer (needs class names, which are available after models are loaded)
_lime_explainer = None

def _get_lime_explainer():
    global _lime_explainer
    if _lime_explainer is None:
        class_names = list(engine.LABEL_MAP_REVERSE.values())
        _lime_explainer = LimeTextExplainer(class_names=class_names)
    return _lime_explainer


CLASS_SUMMARIES = {
    'ham': "This email appears legitimate. No strong spam/phishing indicators found.",
    'spam': "Unsolicited commercial messaging - unwanted but likely not malicious.",
    'phishing': "Patterns typical of phishing - likely attempts to steal credentials or spread malware.",
    'suspicious': "This URL shows mixed signals - some indicators suggest it may be dangerous, but the model cannot confirm phishing with high confidence. Treat with caution.",
}

BEST_PRACTICES = {
    'ham': [
        "Verify sender address carefully.",
        "Hover over links before clicking.",
        "Contact sender through separate channel if suspicious.",
    ],
    'spam': [
        "Don't click 'unsubscribe' in suspicious emails.",
        "Mark as spam in your email client.",
        "Don't reply or auto-reply.",
    ],
    'phishing': [
        "DO NOT click any links or download attachments.",
        "Never enter passwords via email links.",
        "Verify urgency claims through official channels.",
        "Report to IT/security team.",
        "If clicked, change passwords and enable 2FA immediately.",
    ],
}


def get_lime_explanation(text: str, num_features=10):
    # Guard against extremely short texts (LIME crashes on texts with fewer than ~3 words)
    if len(text.split()) < 3:
        return None

    def predict_fn(texts):
        # Use LR + RF weighted average - fast enough for 300 LIME samples and
        # more representative of the ensemble decision than LR alone.
        vecs = engine.tfidf.transform(texts)
        lr_probs = engine.lr_model.predict_proba(vecs)[:, engine.REORDER_IDX]
        rf_probs = engine.rf_model.predict_proba(vecs)[:, engine.REORDER_IDX]
        w_lr = engine.WEIGHTS.get("lr", 0.5)
        w_rf = engine.WEIGHTS.get("rf", 0.5)
        total_w = w_lr + w_rf
        return (w_lr * lr_probs + w_rf * rf_probs) / total_w

    explainer = _get_lime_explainer()
    exp = explainer.explain_instance(text, predict_fn, num_features=num_features, num_samples=300)
    return [{"word": w, "weight": round(wt, 4)} for w, wt in exp.as_list()]


def generate_reasoning(prediction, confidence, model_predictions, lime_features, text="", risk_info=None):
    summary = CLASS_SUMMARIES.get(prediction, "")
    preds = [info['prediction'] for info in model_predictions.values()]
    n_agree = preds.count(prediction)
    n_total = len(preds)

    if n_agree == n_total:
        consensus = f"All {n_total} models agree -- strong consensus."
    elif n_agree >= n_total - 1:
        consensus = f"{n_agree} of {n_total} models agree -- solid consensus."
    else:
        dissenting = [m.replace('_', ' ').title() for m, info in model_predictions.items()
                      if info['prediction'] != prediction]
        consensus = f"Models split: {n_agree}/{n_total} chose '{prediction}'. Dissenting: {', '.join(dissenting)}."

    if confidence >= 0.85:
        conf_note = "High confidence."
    elif confidence >= 0.6:
        conf_note = "Moderate confidence - consider context."
    else:
        conf_note = "Low confidence - mixed signals."

    key_signals = []
    if lime_features:
        positive = [f for f in lime_features if f['weight'] > 0][:5]
        negative = [f for f in lime_features if f['weight'] < 0][:3]
        if positive:
            parts = [f'"{item["word"]}"' for item in positive]
            key_signals.append(f"Words pushing toward '{prediction}': {', '.join(parts)}")
        if negative:
            parts = [f'"{item["word"]}"' for item in negative]
            key_signals.append(f"Words arguing against: {', '.join(parts)}")
        if not key_signals:
            key_signals.append("No strongly weighted words.")
    else:
        key_signals.append("Enable LIME to see word-level signals.")

    attack_type = None
    if text:
        from app.services.risk_engine import classify_attack
        attack_type = classify_attack(text)

    risk_story = ""
    if prediction == "phishing":
        risk_story = f"This appears to be a **{attack_type}** attempt. "
        if attack_type == "Credential Harvesting":
            risk_story += "The attacker likely aims to steal login details by impersonating a trusted service."
        elif attack_type == "Invoice/Billing Scam":
            risk_story += "The attacker tries to trick you into paying a fake invoice."
        else:
            risk_story += "The attacker uses social engineering to manipulate you."
    elif prediction == "spam":
        risk_story = "Unsolicited but likely not malicious - mass marketing spam."
    elif prediction == "suspicious":
        risk_story = "This URL triggered some phishing indicators but not enough for a definitive verdict. Manual review is advised."
    else:
        risk_story = "No malicious intent detected."
    if risk_info:
        risk_story += f" | Risk Score: {risk_info['score']}/100 ({risk_info['level']})"

    return {
        "summary": summary,
        "consensus": consensus,
        "confidence_note": conf_note,
        "key_signals": key_signals,
        "best_practices": BEST_PRACTICES.get(prediction, []),
        "attack_type": attack_type,
        "risk_story": risk_story,
        "risk_score": risk_info.get('score') if risk_info else None,
        "risk_level": risk_info.get('level') if risk_info else None,
    }