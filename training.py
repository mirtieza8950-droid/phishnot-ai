import os

# ── Redirect all model/dataset caches to D: before any library import ─────────
_CACHE = os.environ.get("HF_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "phishnot"))
os.makedirs(os.path.join(_CACHE, "hub"), exist_ok=True)
os.makedirs(os.path.join(_CACHE, "torch"), exist_ok=True)
os.environ.setdefault("HF_HOME",                os.path.join(_CACHE, "hub"))
os.environ.setdefault("HF_HUB_CACHE",           os.path.join(_CACHE, "hub"))
os.environ.setdefault("TRANSFORMERS_CACHE",     os.path.join(_CACHE, "hub"))
os.environ.setdefault("TORCH_HOME",             os.path.join(_CACHE, "torch"))
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
# ─────────────────────────────────────────────────────────────────────────────

import pandas as pd
import numpy as np
import joblib
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from torch.optim import AdamW
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from transformers import (
    DebertaV2Tokenizer, DebertaV2Model,
    RobertaTokenizer, RobertaModel,
    get_linear_schedule_with_warmup,
)
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")
if DEVICE.type == "cuda":
    print(f"GPU: {torch.cuda.get_device_name(0)}")

LABEL_MAP = {'ham': 0, 'phishing': 1, 'spam': 2}
LABEL_MAP_REVERSE = {v: k for k, v in LABEL_MAP.items()}
MAX_LEN    = 256
BATCH_SIZE = 16
EPOCHS     = 4
SAVE_DIR   = "models"

# None = use the full dataset. Set to e.g. 15_000 for a quick test run.
MAX_TRAIN_SAMPLES = None

os.makedirs(SAVE_DIR, exist_ok=True)


# ===============================
# Model definitions
# ===============================

class DeBertaDenseClassifier(nn.Module):
    """DeBERTa-v3-small backbone with custom dense classification head."""
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


# ===============================
# Load & Prepare Data
# ===============================
print("Loading email dataset...")
df = pd.read_csv('final_data_balanced.csv')
X = df['clean_text'].fillna('')
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

if MAX_TRAIN_SAMPLES and len(X_train) > MAX_TRAIN_SAMPLES:
    X_train = X_train.sample(n=MAX_TRAIN_SAMPLES, random_state=42)
    y_train = y_train.loc[X_train.index]
    print(f"Training set capped at {MAX_TRAIN_SAMPLES} samples.")

print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")


# ===============================
# TF-IDF Vectorization
# ===============================
print("\n--- TF-IDF Vectorization ---")
tfidf = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
X_train_tfidf = tfidf.fit_transform(X_train)
X_test_tfidf  = tfidf.transform(X_test)
joblib.dump(tfidf, os.path.join(SAVE_DIR, 'tfidf_vectorizer.pkl'))


# ===============================
# Base Model 1: Logistic Regression
# ===============================
print("\n--- Training Logistic Regression ---")
lr_model = LogisticRegression(max_iter=1000, C=1.0, solver='lbfgs', class_weight='balanced')
lr_model.fit(X_train_tfidf, y_train)
y_pred_lr = lr_model.predict(X_test_tfidf)
print(f"LR Accuracy: {accuracy_score(y_test, y_pred_lr):.4f}")
print(classification_report(y_test, y_pred_lr))
joblib.dump(lr_model, os.path.join(SAVE_DIR, 'logistic_regression.pkl'))


# ===============================
# Base Model 2: Random Forest
# ===============================
print("\n--- Training Random Forest ---")
rf_model = RandomForestClassifier(
    n_estimators=200, random_state=42, class_weight='balanced', n_jobs=-1
)
rf_model.fit(X_train_tfidf, y_train)
y_pred_rf = rf_model.predict(X_test_tfidf)
print(f"RF Accuracy: {accuracy_score(y_test, y_pred_rf):.4f}")
print(classification_report(y_test, y_pred_rf))
joblib.dump(rf_model, os.path.join(SAVE_DIR, 'rf_model.pkl'))


# ===============================
# Shared training/eval helpers
# ===============================

def train_model(model, train_loader, epochs, lr=2e-5, model_name="model", save_path=None):
    model.to(DEVICE)
    optimizer  = AdamW(model.parameters(), lr=lr)
    criterion  = nn.CrossEntropyLoss()
    total_steps = len(train_loader) * epochs
    warmup_steps = max(1, total_steps // 10)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps
    )
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        pbar = tqdm(train_loader, desc=f"{model_name} Epoch {epoch+1}/{epochs}", ncols=100)
        for batch in pbar:
            input_ids, attention_mask, labels = [b.to(DEVICE) for b in batch]
            optimizer.zero_grad()
            logits = model(input_ids, attention_mask=attention_mask)
            loss   = criterion(logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            total_loss += loss.item()
            pbar.set_postfix(loss=f"{loss.item():.4f}")
        avg_loss = total_loss / len(train_loader)
        print(f"  {model_name} Epoch {epoch+1}/{epochs} - Avg Loss: {avg_loss:.4f}")
        if save_path:
            torch.save(model.state_dict(), save_path)
            print(f"  [OK]  Checkpoint saved -> {save_path}  (safe to stop here)")


def evaluate_model(model, test_loader, model_name="model"):
    model.to(DEVICE)
    model.eval()
    y_pred, y_true = [], []
    with torch.no_grad():
        for batch in tqdm(test_loader, desc=f"Evaluating {model_name}", ncols=100):
            input_ids, attention_mask, labels = [b.to(DEVICE) for b in batch]
            logits = model(input_ids, attention_mask=attention_mask)
            preds  = torch.argmax(logits, dim=-1)
            y_pred.extend(preds.cpu().tolist())
            y_true.extend(labels.cpu().tolist())
    acc = accuracy_score(y_true, y_pred)
    print(f"\n{model_name} Accuracy: {acc:.4f}")
    print(classification_report(y_true, y_pred, target_names=list(LABEL_MAP.keys())))
    return acc


def get_dl_predictions(model, loader, name="model"):
    model.to(DEVICE)
    model.eval()
    all_probs = []
    with torch.no_grad():
        for batch in tqdm(loader, desc=f"Probs: {name}", ncols=100):
            input_ids, attention_mask, _ = [b.to(DEVICE) for b in batch]
            logits = model(input_ids, attention_mask=attention_mask)
            probs  = torch.softmax(logits, dim=-1)
            all_probs.append(probs.cpu().numpy())
    return np.vstack(all_probs)


# ===============================
# DeBERTa-v3-small tokenization
# ===============================
print("\n--- Tokenizing for DeBERTa-v3-small ---")
deberta_tokenizer = DebertaV2Tokenizer.from_pretrained('microsoft/deberta-v3-small')

deberta_train_enc = deberta_tokenizer(
    X_train.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)
deberta_test_enc = deberta_tokenizer(
    X_test.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)

y_train_encoded = torch.tensor([LABEL_MAP[l] for l in y_train])
y_test_encoded  = torch.tensor([LABEL_MAP[l] for l in y_test])

deberta_train_loader = DataLoader(
    TensorDataset(deberta_train_enc['input_ids'],
                  deberta_train_enc['attention_mask'],
                  y_train_encoded),
    batch_size=BATCH_SIZE, shuffle=True, drop_last=True,
)
deberta_test_loader = DataLoader(
    TensorDataset(deberta_test_enc['input_ids'],
                  deberta_test_enc['attention_mask'],
                  y_test_encoded),
    batch_size=BATCH_SIZE,
)

# ===============================
# Main Model 1: DeBERTa-v3-small
# ===============================
print("\n--- Training DeBERTa-v3-small + Dense Classifier ---")
deberta_model = DeBertaDenseClassifier(num_classes=3)
train_model(deberta_model, deberta_train_loader, epochs=EPOCHS, lr=2e-5,
            model_name="DeBERTa-v3-small",
            save_path=os.path.join(SAVE_DIR, 'deberta_dense.pth'))
evaluate_model(deberta_model, deberta_test_loader, model_name="DeBERTa-v3-small")

torch.save(deberta_model.state_dict(), os.path.join(SAVE_DIR, 'deberta_dense.pth'))
deberta_tokenizer.save_pretrained(os.path.join(SAVE_DIR, 'deberta_tokenizer'))
print("DeBERTa model and tokenizer saved.")


# ===============================
# DistilRoBERTa tokenization
# ===============================
print("\n--- Tokenizing for DistilRoBERTa ---")
roberta_tokenizer = RobertaTokenizer.from_pretrained('distilroberta-base')

roberta_train_enc = roberta_tokenizer(
    X_train.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)
roberta_test_enc = roberta_tokenizer(
    X_test.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)

roberta_train_loader = DataLoader(
    TensorDataset(roberta_train_enc['input_ids'],
                  roberta_train_enc['attention_mask'],
                  y_train_encoded),
    batch_size=BATCH_SIZE, shuffle=True, drop_last=True,
)
roberta_test_loader = DataLoader(
    TensorDataset(roberta_test_enc['input_ids'],
                  roberta_test_enc['attention_mask'],
                  y_test_encoded),
    batch_size=BATCH_SIZE,
)

# ===============================
# Main Model 2: DistilRoBERTa
# ===============================
print("\n--- Training DistilRoBERTa Dense ---")
distilroberta_model = DistilRobertaDenseClassifier(num_classes=3)

# Load existing checkpoint if available - skip training when weights are good
_dr_path = os.path.join(SAVE_DIR, 'distilroberta.pth')
if os.path.exists(_dr_path):
    distilroberta_model.load_state_dict(torch.load(_dr_path, map_location=DEVICE))
    print("Loaded existing DistilRoBERTa checkpoint - skipping training.")
else:
    train_model(distilroberta_model, roberta_train_loader, epochs=EPOCHS, lr=2e-5,
                model_name="DistilRoBERTa",
                save_path=_dr_path)

evaluate_model(distilroberta_model, roberta_test_loader, model_name="DistilRoBERTa")

torch.save(distilroberta_model.state_dict(), _dr_path)
roberta_tokenizer.save_pretrained(os.path.join(SAVE_DIR, 'distilroberta_tokenizer'))
print("DistilRoBERTa model and tokenizer saved.")


# ===============================
# Ensemble Evaluation
# ===============================
print("\n--- Ensemble Evaluation ---")

trad_classes = list(lr_model.classes_)
reorder_idx  = [trad_classes.index(LABEL_MAP_REVERSE[i]) for i in range(3)]

lr_probs  = lr_model.predict_proba(X_test_tfidf)[:, reorder_idx]
rf_probs  = rf_model.predict_proba(X_test_tfidf)[:, reorder_idx]
db_probs  = get_dl_predictions(deberta_model,       deberta_test_loader, name="DeBERTa")
dr_probs  = get_dl_predictions(distilroberta_model, roberta_test_loader, name="DistilRoBERTa")

W_LR = 0.10
W_RF = 0.15
W_DB = 0.40
W_DR = 0.35

ensemble_probs = W_LR * lr_probs + W_RF * rf_probs + W_DB * db_probs + W_DR * dr_probs
ensemble_preds = np.argmax(ensemble_probs, axis=1)
y_test_labels  = [LABEL_MAP[l] for l in y_test]

print(f"Ensemble Accuracy: {accuracy_score(y_test_labels, ensemble_preds):.4f}")
print(classification_report(y_test_labels, ensemble_preds, target_names=list(LABEL_MAP.keys())))

# Save ensemble config
ensemble_config = {
    'weights': {
        'lr':            W_LR,
        'rf':            W_RF,
        'deberta':       W_DB,
        'distilroberta': W_DR,
    },
    'label_map':         LABEL_MAP,
    'label_map_reverse': LABEL_MAP_REVERSE,
    'trad_class_order':  trad_classes,
    'reorder_idx':       reorder_idx,
    'max_len':           MAX_LEN,
}
joblib.dump(ensemble_config, os.path.join(SAVE_DIR, 'ensemble_config.pkl'))
print("Ensemble config saved.")


# ===============================
# LIME Explanations
# ===============================
print("\n--- Generating LIME Explanations ---")
from lime.lime_text import LimeTextExplainer

lime_explainer = LimeTextExplainer(class_names=list(LABEL_MAP.keys()))

def lime_predict_fn(texts):
    vecs  = tfidf.transform(texts)
    probs = lr_model.predict_proba(vecs)
    return probs[:, reorder_idx]

for label_name in tqdm(list(LABEL_MAP.keys()), desc="LIME", ncols=100):
    sample = X_test[y_test == label_name].iloc[0]
    exp = lime_explainer.explain_instance(sample, lime_predict_fn, num_features=10, num_samples=500)
    exp.save_to_file(os.path.join(SAVE_DIR, f'lime_explanation_{label_name}.html'))

print("\n--- All models trained and saved! ---")
print(f"Models saved to: {os.path.abspath(SAVE_DIR)}")
