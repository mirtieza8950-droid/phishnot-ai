"""
Ensemble engine: model definitions, loading, prediction, and versioned meta-learner.

Ensemble members:
  - Logistic Regression        (TF-IDF, weight 0.10)
  - Random Forest              (TF-IDF, weight 0.15)
  - DeBERTa-v3-small Dense    (contextual, weight 0.40)
  - DistilRoBERTa Dense       (contextual, weight 0.35)

Spam threshold: 0.42 (lower than default 0.5 to compensate for class imbalance).
"""
import os
import numpy as np
import joblib
import torch
import torch.nn as nn
from transformers import (
    DebertaV2Tokenizer, DebertaV2Model,
    RobertaTokenizer, RobertaModel,
)
from peft import PeftModel
from app.utils.url_features import extract_url_features, get_feature_names as get_url_feature_names
from app.core.config import settings

# ── Module-level model references ─────────────────────────────────────────────
tfidf           = None
lr_model        = None
rf_model        = None
ensemble_config = None
LABEL_MAP        = {}
LABEL_MAP_REVERSE = {}
WEIGHTS          = {}
REORDER_IDX      = []
MAX_LEN          = settings.MAX_LEN

# DeBERTa-v3-small
deberta_tokenizer = None
deberta_model     = None
deberta_lora      = None  # LoRA adapter (if loaded)

# DistilRoBERTa
distilroberta_tokenizer = None
distilroberta_model     = None
distilroberta_lora      = None  # LoRA adapter (if loaded)

url_model               = None
url_transformer_tokenizer = None
url_transformer_model     = None
meta_model       = None
meta_le          = None
use_meta_learner = False

DEVICE = torch.device(settings.DEVICE)

# Per-class decision thresholds (overrides argmax when exceeded)
SPAM_THRESHOLD = 0.42


# ── Model classes ──────────────────────────────────────────────────────────────

class DeBertaDenseClassifier(nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()
        self.deberta = DebertaV2Model.from_pretrained('microsoft/deberta-v3-small').float()
        h = self.deberta.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(h, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, input_ids, attention_mask=None, token_type_ids=None):
        out = self.deberta(input_ids=input_ids, attention_mask=attention_mask)
        return self.classifier(out.last_hidden_state[:, 0, :])


class URLTransformerClassifier(nn.Module):
    """DistilRoBERTa fine-tuned on raw URL strings. Binary: 0=legitimate, 1=phishing."""
    def __init__(self):
        super().__init__()
        self.roberta = RobertaModel.from_pretrained('distilroberta-base')
        h = self.roberta.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(h, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, 2),
        )

    def forward(self, input_ids, attention_mask=None):
        out = self.roberta(input_ids=input_ids, attention_mask=attention_mask)
        return self.classifier(out.last_hidden_state[:, 0, :])


class DistilRobertaDenseClassifier(nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()
        self.roberta = RobertaModel.from_pretrained('distilroberta-base')
        h = self.roberta.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(h, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, input_ids, attention_mask=None):
        out = self.roberta(input_ids=input_ids, attention_mask=attention_mask)
        return self.classifier(out.last_hidden_state[:, 0, :])


# ── Model loading ──────────────────────────────────────────────────────────────

def load_all_models():
    global tfidf, lr_model, rf_model, ensemble_config
    global LABEL_MAP, LABEL_MAP_REVERSE, WEIGHTS, REORDER_IDX, MAX_LEN, DEVICE
    global deberta_tokenizer, deberta_model, deberta_lora
    global distilroberta_tokenizer, distilroberta_model, distilroberta_lora
    global url_model, url_transformer_tokenizer, url_transformer_model
    global meta_model, meta_le, use_meta_learner

    print("Loading models...")

    tfidf    = joblib.load(settings.TFIDF_PATH)
    lr_model = joblib.load(settings.LR_PATH)

    # RF - support legacy svm_model.pkl filename
    rf_path = settings.RF_PATH
    if not os.path.exists(rf_path):
        rf_path = os.path.join(settings.MODELS_DIR, "svm_model.pkl")
    rf_model = joblib.load(rf_path)

    ensemble_config   = joblib.load(settings.ENSEMBLE_CONFIG_PATH)
    LABEL_MAP         = ensemble_config['label_map']
    LABEL_MAP_REVERSE = ensemble_config['label_map_reverse']
    WEIGHTS           = dict(ensemble_config['weights'])
    REORDER_IDX       = ensemble_config['reorder_idx']

    # ── Migrate old weight keys ────────────────────────────────────────────────
    if 'svm' in WEIGHTS and 'rf' not in WEIGHTS:
        WEIGHTS['rf'] = WEIGHTS.pop('svm')
    if 'cnn_transformer' in WEIGHTS and 'distilroberta' not in WEIGHTS:
        WEIGHTS['distilroberta'] = WEIGHTS.pop('cnn_transformer')
    # Drop broken DistilBERT key if present in a stale ensemble_config
    WEIGHTS.pop('distilbert', None)

    # ── DeBERTa-v3-small ───────────────────────────────────────────────────────
    db_tok_path = settings.DEBERTA_TOKENIZER_PATH
    if os.path.isdir(db_tok_path):
        deberta_tokenizer = DebertaV2Tokenizer.from_pretrained(db_tok_path)
    else:
        deberta_tokenizer = DebertaV2Tokenizer.from_pretrained('microsoft/deberta-v3-small')

    deberta_model = DeBertaDenseClassifier(3)
    if os.path.exists(settings.DEBERTA_PATH):
        deberta_model.load_state_dict(
            torch.load(settings.DEBERTA_PATH, map_location=DEVICE)
        )
        print("[OK]  DeBERTa-v3-small weights loaded.")
    else:
        print("[WARN]   deberta_dense.pth not found - run training.py to produce it.")

    # ── Load LoRA adapters (if trained) ───────────────────────────────────────
    lora_dir = os.path.join(settings.MODELS_DIR, 'deberta_lora')
    if os.path.isdir(lora_dir) and os.path.exists(settings.DEBERTA_PATH):
        try:
            deberta_lora = PeftModel.from_pretrained(
                deberta_model.deberta, lora_dir
            )
            deberta_lora.to(DEVICE).eval()
            print("[OK]  DeBERTa LoRA adapters loaded.")
        except Exception as e:
            print(f"[WARN]   DeBERTa LoRA load failed: {e}")
            deberta_lora = None
    else:
        deberta_lora = None

    try:
        deberta_model.to(DEVICE).eval()
    except torch.cuda.OutOfMemoryError:
        print("[WARN] GPU OOM for DeBERTa — falling back to CPU")
        torch.cuda.empty_cache()
        DEVICE = torch.device("cpu")
        deberta_model.to(DEVICE).eval()

    # ── DistilRoBERTa ──────────────────────────────────────────────────────────
    dr_tokenizer_path = settings.DISTILROBERTA_TOKENIZER_PATH
    if os.path.isdir(dr_tokenizer_path):
        distilroberta_tokenizer = RobertaTokenizer.from_pretrained(dr_tokenizer_path)
    else:
        distilroberta_tokenizer = RobertaTokenizer.from_pretrained('distilroberta-base')

    distilroberta_model = DistilRobertaDenseClassifier(3)
    if os.path.exists(settings.DISTILROBERTA_PATH):
        distilroberta_model.load_state_dict(
            torch.load(settings.DISTILROBERTA_PATH, map_location=DEVICE)
        )
        print("[OK]  DistilRoBERTa weights loaded.")
    else:
        print("[WARN]   distilroberta.pth not found - run training.py to produce it.")

    # ── Load LoRA adapters (if trained) ───────────────────────────────────────
    lora_dir = os.path.join(settings.MODELS_DIR, 'distilroberta_lora')
    if os.path.isdir(lora_dir) and os.path.exists(settings.DISTILROBERTA_PATH):
        try:
            distilroberta_lora = PeftModel.from_pretrained(
                distilroberta_model.roberta, lora_dir
            )
            distilroberta_lora.to(DEVICE).eval()
            print("[OK]  DistilRoBERTa LoRA adapters loaded.")
        except Exception as e:
            print(f"[WARN]   DistilRoBERTa LoRA load failed: {e}")
            distilroberta_lora = None
    else:
        distilroberta_lora = None

    try:
        distilroberta_model.to(DEVICE).eval()
    except torch.cuda.OutOfMemoryError:
        print("[WARN] GPU OOM for DistilRoBERTa — falling back to CPU")
        torch.cuda.empty_cache()
        DEVICE = torch.device("cpu")
        distilroberta_model.to(DEVICE).eval()

    # ── URL lexical model (GradientBoosting) ──────────────────────────────────
    url_model = joblib.load(settings.URL_MODEL_PATH)

    # ── URL transformer (DistilRoBERTa on raw URLs) ────────────────────────────
    ut_tok_path = settings.URL_TRANSFORMER_TOKENIZER_PATH
    if os.path.isdir(ut_tok_path):
        url_transformer_tokenizer = RobertaTokenizer.from_pretrained(ut_tok_path)
    else:
        url_transformer_tokenizer = RobertaTokenizer.from_pretrained('distilroberta-base')

    url_transformer_model = URLTransformerClassifier()
    if os.path.exists(settings.URL_TRANSFORMER_PATH):
        url_transformer_model.load_state_dict(
            torch.load(settings.URL_TRANSFORMER_PATH, map_location=DEVICE)
        )
        print("[OK]  URL transformer weights loaded.")
    else:
        print("[WARN]   url_transformer.pth not found - run train_url_transformer.py.")
    try:
        url_transformer_model.to(DEVICE).eval()
    except torch.cuda.OutOfMemoryError:
        print("[WARN] GPU OOM for URL Transformer — falling back to CPU")
        torch.cuda.empty_cache()
        DEVICE = torch.device("cpu")
        url_transformer_model.to(DEVICE).eval()

    # ── Version-pinned meta-learner ────────────────────────────────────────────
    version_file = os.path.join(settings.MODELS_DIR, "meta_version.txt")
    if os.path.exists(version_file):
        with open(version_file) as f:
            version = f.read().strip()
        meta_path = os.path.join(settings.MODELS_DIR, f"meta_learner_v{version}.pkl")
    else:
        meta_path = os.path.join(settings.MODELS_DIR, "meta_learner.pkl")

    label_encoder_path = os.path.join(settings.MODELS_DIR, "meta_label_encoder.pkl")
    if os.path.exists(meta_path) and os.path.exists(label_encoder_path):
        meta_model = joblib.load(meta_path)
        meta_le    = joblib.load(label_encoder_path)
        use_meta_learner = True
        tag = meta_path.split('_v')[-1].split('.')[0] if '_v' in meta_path else 'latest'
        print(f"[OK]  Meta-learner loaded (v{tag}).")
    else:
        print("[INFO]   Meta-learner not found. Using weighted average ensemble.")

    print("All models loaded successfully!")


# ── Prediction helpers ─────────────────────────────────────────────────────────

def _model_breakdown(probs_row, weight):
    idx = int(np.argmax(probs_row))
    return {
        'prediction':    LABEL_MAP_REVERSE[idx],
        'confidence':    round(float(probs_row[idx]), 4),
        'weight':        weight,
        'probabilities': {LABEL_MAP_REVERSE[i]: round(float(probs_row[i]), 4) for i in range(3)},
    }


def _apply_thresholds(probs: np.ndarray) -> int:
    """
    Apply per-class decision thresholds before argmax.
    Spam wins if its probability meets SPAM_THRESHOLD and beats ham -
    prevents the minority-class bias from suppressing real spam.
    """
    ham_idx  = next(k for k, v in LABEL_MAP_REVERSE.items() if v == 'ham')
    spam_idx = next(k for k, v in LABEL_MAP_REVERSE.items() if v == 'spam')
    if probs[spam_idx] >= SPAM_THRESHOLD and probs[spam_idx] > probs[ham_idx]:
        return spam_idx
    return int(np.argmax(probs))


def predict_email_ensemble(text: str):
    # ── Classical models ───────────────────────────────────────────────────────
    text_tfidf = tfidf.transform([text])
    lr_probs   = lr_model.predict_proba(text_tfidf)[:, REORDER_IDX]
    rf_probs   = rf_model.predict_proba(text_tfidf)[:, REORDER_IDX]

    # ── DeBERTa-v3-small ──────────────────────────────────────────────────────
    db_enc = deberta_tokenizer(text, padding='max_length', truncation=True,
                               max_length=MAX_LEN, return_tensors='pt')
    db_ids  = db_enc['input_ids'].to(DEVICE)
    db_mask = db_enc['attention_mask'].to(DEVICE)

    # ── DistilRoBERTa ──────────────────────────────────────────────────────────
    dr_enc = distilroberta_tokenizer(text, padding='max_length', truncation=True,
                                     max_length=MAX_LEN, return_tensors='pt')
    dr_ids  = dr_enc['input_ids'].to(DEVICE)
    dr_mask = dr_enc['attention_mask'].to(DEVICE)

    with torch.no_grad():
        # Use LoRA adapter if available, else base model
        if deberta_lora is not None:
            db_out = deberta_lora(input_ids=db_ids, attention_mask=db_mask)
            # PeftModel SEQ_CLS returns logits directly, or BaseModelOutput
            if hasattr(db_out, 'logits'):
                db_probs = torch.softmax(db_out.logits, dim=-1).cpu().numpy()
            elif hasattr(db_out, 'last_hidden_state'):
                db_logits = deberta_model.classifier(db_out.last_hidden_state[:, 0, :])
                db_probs = torch.softmax(db_logits, dim=-1).cpu().numpy()
            else:
                db_logits = deberta_model.classifier(db_out[:, 0, :])
                db_probs = torch.softmax(db_logits, dim=-1).cpu().numpy()
        else:
            db_probs = torch.softmax(deberta_model(db_ids, db_mask), dim=-1).cpu().numpy()

        if distilroberta_lora is not None:
            dr_out = distilroberta_lora(input_ids=dr_ids, attention_mask=dr_mask)
            if hasattr(dr_out, 'logits'):
                dr_probs = torch.softmax(dr_out.logits, dim=-1).cpu().numpy()
            elif hasattr(dr_out, 'last_hidden_state'):
                dr_logits = distilroberta_model.classifier(dr_out.last_hidden_state[:, 0, :])
                dr_probs = torch.softmax(dr_logits, dim=-1).cpu().numpy()
            else:
                dr_logits = distilroberta_model.classifier(dr_out[:, 0, :])
                dr_probs = torch.softmax(dr_logits, dim=-1).cpu().numpy()
        else:
            dr_probs = torch.softmax(distilroberta_model(dr_ids, dr_mask), dim=-1).cpu().numpy()

    # ── Ensemble ───────────────────────────────────────────────────────────────
    w_lr = WEIGHTS.get('lr',            0.10)
    w_rf = WEIGHTS.get('rf',            0.15)
    w_db = WEIGHTS.get('deberta',       0.40)
    w_dr = WEIGHTS.get('distilroberta', 0.35)

    if use_meta_learner and meta_model is not None:
        stacked = np.concatenate(
            [lr_probs[0], rf_probs[0], db_probs[0], dr_probs[0]]
        ).reshape(1, -1)
        try:
            final_probs    = meta_model.predict_proba(stacked)[0]
            ensemble_probs = np.zeros((1, 3))
            for i, cls_label in enumerate(meta_model.classes_):
                col = (int(meta_le.transform([cls_label])[0])
                       if meta_le is not None and hasattr(meta_le, 'transform')
                       else int(cls_label))
                if 0 <= col < 3:
                    ensemble_probs[0, col] = final_probs[i]
            if abs(ensemble_probs[0].sum() - 1.0) > 0.05:
                raise ValueError("class ordering mismatch")
        except Exception:
            ensemble_probs = (w_lr * lr_probs + w_rf * rf_probs +
                              w_db * db_probs  + w_dr * dr_probs)
    else:
        ensemble_probs = (w_lr * lr_probs + w_rf * rf_probs +
                          w_db * db_probs  + w_dr * dr_probs)

    pred_idx   = _apply_thresholds(ensemble_probs[0])
    pred_label = LABEL_MAP_REVERSE[pred_idx]
    confidence = float(ensemble_probs[0][pred_idx])
    all_probs  = {LABEL_MAP_REVERSE[i]: round(float(ensemble_probs[0][i]), 4) for i in range(3)}
    model_preds = {
        'logistic_regression': _model_breakdown(lr_probs[0], w_lr),
        'random_forest':       _model_breakdown(rf_probs[0], w_rf),
        'deberta_dense':       _model_breakdown(db_probs[0], w_db),
        'distilroberta_dense': _model_breakdown(dr_probs[0], w_dr),
    }
    return pred_label, confidence, all_probs, model_preds


# ── URL prediction ─────────────────────────────────────────────────────────────

# Weights: transformer is primary; GB stays as a fast lexical sanity-check.
_URL_W_TRANSFORMER = 0.70
_URL_W_GB          = 0.30


def predict_url(url: str) -> tuple[float, float, dict]:
    """
    Return (phishing_prob, legitimate_prob, model_breakdown).

    Falls back to GB-only if the URL transformer wasn't trained yet.
    Class order: index 0 = legitimate, index 1 = phishing.
    """
    feature_names = get_url_feature_names()
    features = extract_url_features(url)
    X = np.array([[features[f] for f in feature_names]])
    gb_proba = url_model.predict_proba(X)[0]   # [P(legit), P(phish)]

    # Check if the transformer is actually trained (weights loaded)
    transformer_ready = os.path.exists(settings.URL_TRANSFORMER_PATH)

    if transformer_ready:
        enc = url_transformer_tokenizer(
            url, padding='max_length', truncation=True,
            max_length=settings.URL_TRANSFORMER_MAX_LEN, return_tensors='pt'
        )
        with torch.no_grad():
            tr_proba = torch.softmax(
                url_transformer_model(enc['input_ids'].to(DEVICE),
                                      enc['attention_mask'].to(DEVICE)),
                dim=-1
            ).cpu().numpy()[0]   # [P(legit), P(phish)]

        ensemble = _URL_W_TRANSFORMER * tr_proba + _URL_W_GB * gb_proba
        breakdown = {
            'url_transformer':    {'prediction': 'phishing' if tr_proba[1] > 0.5 else 'legitimate',
                                   'confidence': round(float(max(tr_proba)), 4),
                                   'weight': _URL_W_TRANSFORMER,
                                   'probabilities': {'legitimate': round(float(tr_proba[0]), 4),
                                                     'phishing':   round(float(tr_proba[1]), 4)}},
            'gradient_boosting':  {'prediction': 'phishing' if gb_proba[1] > 0.5 else 'legitimate',
                                   'confidence': round(float(max(gb_proba)), 4),
                                   'weight': _URL_W_GB,
                                   'probabilities': {'legitimate': round(float(gb_proba[0]), 4),
                                                     'phishing':   round(float(gb_proba[1]), 4)}},
        }
    else:
        ensemble = gb_proba
        breakdown = {
            'gradient_boosting': {'prediction': 'phishing' if gb_proba[1] > 0.5 else 'legitimate',
                                  'confidence': round(float(max(gb_proba)), 4),
                                  'weight': 1.0,
                                  'probabilities': {'legitimate': round(float(gb_proba[0]), 4),
                                                    'phishing':   round(float(gb_proba[1]), 4)}},
        }

    return float(ensemble[1]), float(ensemble[0]), breakdown
