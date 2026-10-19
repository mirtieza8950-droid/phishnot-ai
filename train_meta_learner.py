"""
train_meta_learner.py — Train the XGBoost stacking meta-learner.

Uses the 4 active base models (LR, RF, DeBERTa, DistilRoBERTa) to generate
stacked predictions on the validation set + confirmed feedback corrections,
then trains XGBoost on top.

Outputs:
  models/meta_learner_v{N}.pkl
  models/meta_label_encoder.pkl
  models/meta_version.txt

Usage:
  python train_meta_learner.py                    # full retrain
  python train_meta_learner.py --incremental      # add feedback to existing data
  python train_meta_learner.py --min-samples 100  # skip if fewer samples
"""
import os
import sys
import argparse
import shutil
import time

import numpy as np
import pandas as pd
import joblib
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

# ── Cache redirect ────────────────────────────────────────────────────────────
_CACHE = os.environ.get("HF_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "phishnot"))
os.makedirs(os.path.join(_CACHE, "hub"), exist_ok=True)
os.makedirs(os.path.join(_CACHE, "torch"), exist_ok=True)
os.environ.setdefault("HF_HOME",            os.environ.get("HF_HOME", _CACHE))
os.environ.setdefault("HF_HUB_CACHE",       os.path.join(_CACHE, "hub"))
os.environ.setdefault("TRANSFORMERS_CACHE", os.path.join(_CACHE, "hub"))
os.environ.setdefault("TORCH_HOME",         os.path.join(_CACHE, "torch"))
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

parser = argparse.ArgumentParser()
parser.add_argument("--incremental", action="store_true",
                    help="Add feedback data to existing validation data")
parser.add_argument("--min-samples", type=int, default=50,
                    help="Minimum stacked samples required to train")
parser.add_argument("--feedback-min-trust", type=float, default=0.8,
                    help="Minimum trust score for feedback inclusion")
parser.add_argument("--feedback-min-consensus", type=int, default=3,
                    help="Minimum consensus count for feedback inclusion")
args = parser.parse_args()

MODELS_DIR = "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print(f"Device: {DEVICE}")

# ── Load base models ──────────────────────────────────────────────────────────
print("\nLoading base models...")

tfidf    = joblib.load(f"{MODELS_DIR}/tfidf_vectorizer.pkl")
lr_model = joblib.load(f"{MODELS_DIR}/logistic_regression.pkl")

rf_path = f"{MODELS_DIR}/rf_model.pkl"
if not os.path.exists(rf_path):
    rf_path = f"{MODELS_DIR}/svm_model.pkl"
rf_model = joblib.load(rf_path)

ensemble_config = joblib.load(f"{MODELS_DIR}/ensemble_config.pkl")
REORDER_IDX = ensemble_config['reorder_idx']
LABEL_MAP   = ensemble_config['label_map']
MAX_LEN     = ensemble_config.get('max_len', 256)

# DeBERTa
from transformers import DebertaV2Tokenizer, DebertaV2Model
db_tok_path = f"{MODELS_DIR}/deberta_tokenizer"
if os.path.isdir(db_tok_path):
    deberta_tokenizer = DebertaV2Tokenizer.from_pretrained(db_tok_path)
else:
    deberta_tokenizer = DebertaV2Tokenizer.from_pretrained('microsoft/deberta-v3-small')

class DeBertaDenseClassifier(torch.nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()
        self.deberta = DebertaV2Model.from_pretrained('microsoft/deberta-v3-small').float()
        h = self.deberta.config.hidden_size
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(h, 256), torch.nn.ReLU(), torch.nn.Dropout(0.3),
            torch.nn.Linear(256, 64), torch.nn.ReLU(), torch.nn.Dropout(0.2),
            torch.nn.Linear(64, num_classes),
        )
    def forward(self, input_ids, attention_mask=None):
        out = self.deberta(input_ids=input_ids, attention_mask=attention_mask)
        return self.classifier(out.last_hidden_state[:, 0, :])

deberta_model = DeBertaDenseClassifier(3)
deberta_model.load_state_dict(
    torch.load(f"{MODELS_DIR}/deberta_dense.pth", map_location=DEVICE)
)
deberta_model.to(DEVICE).eval()

# DistilRoBERTa
from transformers import RobertaTokenizer, RobertaModel
dr_tok_path = f"{MODELS_DIR}/distilroberta_tokenizer"
if os.path.isdir(dr_tok_path):
    dr_tokenizer = RobertaTokenizer.from_pretrained(dr_tok_path)
else:
    dr_tokenizer = RobertaTokenizer.from_pretrained('distilroberta-base')

class DistilRobertaDenseClassifier(torch.nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()
        self.roberta = RobertaModel.from_pretrained('distilroberta-base')
        h = self.roberta.config.hidden_size
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(h, 256), torch.nn.ReLU(), torch.nn.Dropout(0.3),
            torch.nn.Linear(256, 64), torch.nn.ReLU(), torch.nn.Dropout(0.2),
            torch.nn.Linear(64, num_classes),
        )
    def forward(self, input_ids, attention_mask=None):
        out = self.roberta(input_ids=input_ids, attention_mask=attention_mask)
        return self.classifier(out.last_hidden_state[:, 0, :])

dr_model = DistilRobertaDenseClassifier(3)
dr_model.load_state_dict(
    torch.load(f"{MODELS_DIR}/distilroberta.pth", map_location=DEVICE)
)
dr_model.to(DEVICE).eval()

print("All base models loaded.")


# ── Stacking: generate meta-features ──────────────────────────────────────────

def encode_text(text: str) -> np.ndarray:
    """Run all 4 base models on a text and return stacked 12-dim feature vector."""
    # Classical
    tfidf_vec = tfidf.transform([text])
    lr_p = lr_model.predict_proba(tfidf_vec)[:, REORDER_IDX][0]
    rf_p = rf_model.predict_proba(tfidf_vec)[:, REORDER_IDX][0]

    # DeBERTa
    db_enc = deberta_tokenizer(text, padding='max_length', truncation=True,
                               max_length=MAX_LEN, return_tensors='pt')
    with torch.no_grad():
        db_logits = deberta_model(
            db_enc['input_ids'].to(DEVICE), db_enc['attention_mask'].to(DEVICE)
        )
        db_p = torch.softmax(db_logits, dim=-1).cpu().numpy()[0]

    # DistilRoBERTa
    dr_enc = dr_tokenizer(text, padding='max_length', truncation=True,
                          max_length=MAX_LEN, return_tensors='pt')
    with torch.no_grad():
        dr_logits = dr_model(
            dr_enc['input_ids'].to(DEVICE), dr_enc['attention_mask'].to(DEVICE)
        )
        dr_p = torch.softmax(dr_logits, dim=-1).cpu().numpy()[0]

    return np.concatenate([lr_p, rf_p, db_p, dr_p])


# ── Load validation data ──────────────────────────────────────────────────────
print("\nLoading validation data...")
val_path = "validation_data.csv"
if os.path.exists(val_path):
    val_df = pd.read_csv(val_path)
    base_texts = val_df["clean_text"].fillna("").tolist()
    base_labels = val_df["label"].tolist()
    print(f"  Validation set: {len(base_texts)} samples")
else:
    print("  [WARN] validation_data.csv not found — will use feedback data only.")
    base_texts = []
    base_labels = []


# ── Load confirmed feedback corrections ───────────────────────────────────────
print("Loading confirmed feedback corrections...")
try:
    from app.services.self_training_pipeline import get_confirmed_corrections
    corrections = get_confirmed_corrections(
        min_consensus=args.feedback_min_consensus,
        min_trust=args.feedback_min_trust,
    )
    feedback_texts = [c["input_text"] for c in corrections]
    feedback_labels = [c["user_label"] for c in corrections]
    feedback_weights = [c["trust_score"] for c in corrections]
    print(f"  Feedback corrections: {len(feedback_texts)} samples")
except Exception as e:
    print(f"  [WARN] Could not load feedback: {e}")
    feedback_texts = []
    feedback_labels = []
    feedback_weights = []


# ── Combine data ──────────────────────────────────────────────────────────────
all_texts = base_texts + feedback_texts
all_labels = base_labels + feedback_labels
all_weights = [1.0] * len(base_texts) + feedback_weights

if len(all_texts) < args.min_samples:
    print(f"\n[ERROR] Not enough data ({len(all_texts)} < {args.min_samples}). "
          "Need more validation data or confirmed feedback.")
    sys.exit(1)

print(f"\nTotal training data: {len(all_texts)} samples")
print(f"  Base validation: {len(base_texts)}")
print(f"  Feedback corrections: {len(feedback_texts)}")


# ── Generate stacked predictions ──────────────────────────────────────────────
print("\nGenerating stacked predictions from all 4 base models (this takes a few minutes)...")
X_meta = []
y_meta = []
weights_meta = []

le = LabelEncoder()
all_labels_encoded = le.fit_transform(all_labels)

for i, (text, label_enc, weight) in enumerate(zip(all_texts, all_labels_encoded, all_weights)):
    if i % 100 == 0:
        print(f"  Encoding {i}/{len(all_texts)}...")
    try:
        features = encode_text(text)
        X_meta.append(features)
        y_meta.append(label_enc)
        weights_meta.append(weight)
    except Exception as e:
        print(f"  [WARN] Skipping sample {i}: {e}")
        continue

X_meta = np.array(X_meta)
y_meta = np.array(y_meta)
w_meta = np.array(weights_meta)

print(f"  Stacked features shape: {X_meta.shape}")


# ── Train/test split ──────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test, w_train, w_test = train_test_split(
    X_meta, y_meta, w_meta, test_size=0.2, random_state=42, stratify=y_meta
)

print(f"  Train: {len(X_train)} | Test: {len(X_test)}")


# ── Train XGBoost ─────────────────────────────────────────────────────────────
print("\nTraining XGBoost meta-learner...")
t0 = time.time()

meta_model = XGBClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="mlogloss",
    random_state=42,
)
meta_model.fit(X_train, y_train, sample_weight=w_train)

train_time = time.time() - t0
print(f"  Training time: {train_time:.1f}s")


# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = meta_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nMeta-learner accuracy: {accuracy:.4f}")
print(classification_report(y_test, y_pred, target_names=le.classes_))


# ── Load existing meta-learner for comparison ──────────────────────────────────
version_file = f"{MODELS_DIR}/meta_version.txt"
current_v = 1
if os.path.exists(version_file):
    with open(version_file) as f:
        current_v = int(f.read().strip())

old_accuracy = None
old_meta_path = f"{MODELS_DIR}/meta_learner_v{current_v}.pkl"
if os.path.exists(old_meta_path):
    old_meta = joblib.load(old_meta_path)
    y_pred_old = old_meta.predict(X_test)
    old_accuracy = accuracy_score(y_test, y_pred_old)
    print(f"  Old meta-learner accuracy: {old_accuracy:.4f}")

    if accuracy < old_accuracy:
        print(f"\n[WARN] New model ({accuracy:.4f}) is WORSE than old ({old_accuracy:.4f}). "
              "Keeping old model.")
        sys.exit(0)


# ── Save ──────────────────────────────────────────────────────────────────────
new_v = current_v + 1
new_path = f"{MODELS_DIR}/meta_learner_v{new_v}.pkl"
joblib.dump(meta_model, new_path)
joblib.dump(le, f"{MODELS_DIR}/meta_label_encoder.pkl")

tmp_version = version_file + ".tmp"
with open(tmp_version, "w") as f:
    f.write(str(new_v))
shutil.move(tmp_version, version_file)

print(f"\n[OK]  Meta-learner v{new_v} saved.")
print(f"  Accuracy: {accuracy:.4f}")
print(f"  Samples: {len(all_texts)} ({len(base_texts)} validation + {len(feedback_texts)} feedback)")
if old_accuracy:
    delta = accuracy - old_accuracy
    print(f"  vs old: {'+' if delta >= 0 else ''}{delta:.4f}")
