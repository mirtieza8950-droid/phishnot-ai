"""
Train all models + stacked meta-learner (XGBoost).
Run once to produce:
- models/tfidf_vectorizer.pkl
- models/logistic_regression.pkl
- models/svm_model.pkl
- models/distilbert_dense_finetuned.pth   (improved DistilBERT)
- models/cnn_transformer.pth
- models/ensemble_config.pkl
- models/meta_learner.pkl                 (stacking model)
- models/meta_label_encoder.pkl
- models/label_to_id.pkl
"""
import pandas as pd
import numpy as np
import os
import joblib
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from torch.optim import AdamW
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score
from transformers import DistilBertTokenizer, DistilBertModel
from tqdm import tqdm
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings("ignore")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")
if DEVICE.type == "cuda":
    print(f"GPU: {torch.cuda.get_device_name(0)}")

LABEL_MAP = {'ham': 0, 'phishing': 1, 'spam': 2}
LABEL_MAP_REVERSE = {v: k for k, v in LABEL_MAP.items()}
MAX_LEN = 256
BATCH_SIZE = 16
EPOCHS = 4   # fine-tuning pre-trained model
SAVE_DIR = "models"
os.makedirs(SAVE_DIR, exist_ok=True)

# ===============================
# Model Definitions (unchanged)
# ===============================
class CNNTransformerHybrid(nn.Module):
    def __init__(self, vocab_size, embed_dim=256, num_classes=3,
                 num_filters=128, kernel_sizes=[3, 4, 5],
                 nhead=4, num_transformer_layers=2, max_len=MAX_LEN):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_embedding = nn.Embedding(max_len, embed_dim)
        self.convs = nn.ModuleList([
            nn.Conv1d(embed_dim, num_filters, kernel_size=k, padding=k // 2)
            for k in kernel_sizes
        ])
        self.cnn_bn = nn.LayerNorm(num_filters * len(kernel_sizes))
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=nhead, dim_feedforward=512,
            dropout=0.1, batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_transformer_layers)
        combined_dim = num_filters * len(kernel_sizes) + embed_dim
        self.classifier = nn.Sequential(
            nn.Linear(combined_dim, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )

    def forward(self, input_ids, attention_mask=None):
        batch_size, seq_len = input_ids.shape
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch_size, -1)
        x = self.embedding(input_ids) + self.pos_embedding(positions)
        x_cnn = x.permute(0, 2, 1)
        conv_outs = [torch.relu(conv(x_cnn)).max(dim=2)[0] for conv in self.convs]
        cnn_out = self.cnn_bn(torch.cat(conv_outs, dim=1))
        src_key_padding_mask = (attention_mask == 0) if attention_mask is not None else None
        trans_out = self.transformer_encoder(x, src_key_padding_mask=src_key_padding_mask).mean(dim=1)
        return self.classifier(torch.cat([cnn_out, trans_out], dim=1))


class DistilBertDenseClassifier(nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()
        self.distilbert = DistilBertModel.from_pretrained('distilbert-base-uncased')
        hidden_size = self.distilbert.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )

    def forward(self, input_ids, attention_mask=None):
        outputs = self.distilbert(input_ids=input_ids, attention_mask=attention_mask)
        cls_output = outputs.last_hidden_state[:, 0, :]
        return self.classifier(cls_output)


# ===============================
# Load & Prepare Data
# ===============================
print("Loading email dataset...")
df = pd.read_csv('final_data_balanced.csv')
X = df['clean_text'].fillna('')
y = df['label']

# Original train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Train: {len(X_train)}, Test: {len(X_test)}")

# ===============================
# TF-IDF Vectorization
# ===============================
print("\n--- TF-IDF Vectorization ---")
tfidf = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
X_train_tfidf = tfidf.fit_transform(X_train)
X_test_tfidf = tfidf.transform(X_test)
joblib.dump(tfidf, os.path.join(SAVE_DIR, 'tfidf_vectorizer.pkl'))

# ===============================
# Base Model 1: Logistic Regression
# ===============================
print("\n--- Training Logistic Regression ---")
lr_model = LogisticRegression(max_iter=1000, C=1.0, solver='lbfgs')
lr_model.fit(X_train_tfidf, y_train)
y_pred_lr = lr_model.predict(X_test_tfidf)
print(f"LR Accuracy: {accuracy_score(y_test, y_pred_lr):.4f}")
print(classification_report(y_test, y_pred_lr))
joblib.dump(lr_model, os.path.join(SAVE_DIR, 'logistic_regression.pkl'))

# ===============================
# Base Model 2: Random Forest
# ===============================
print("\n--- Training Random Forest ---")
from sklearn.ensemble import RandomForestClassifier
rf_model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced', n_jobs=-1)
rf_model.fit(X_train_tfidf, y_train)
y_pred_rf = rf_model.predict(X_test_tfidf)
print(f"RF Accuracy: {accuracy_score(y_test, y_pred_rf):.4f}")
print(classification_report(y_test, y_pred_rf))
joblib.dump(rf_model, os.path.join(SAVE_DIR, 'rf_model.pkl'))

# ===============================
# Tokenization for Deep Models
# ===============================
print("\n--- Tokenizing for DistilBERT ---")
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')

def tokenize_batch(texts, max_length=MAX_LEN):
    return tokenizer(texts, padding='max_length', truncation=True,
                     max_length=max_length, return_tensors='pt')

train_enc = tokenize_batch(X_train.tolist())
test_enc = tokenize_batch(X_test.tolist())

y_train_ids = torch.tensor([LABEL_MAP[l] for l in y_train])
y_test_ids = torch.tensor([LABEL_MAP[l] for l in y_test])

train_dataset = TensorDataset(train_enc['input_ids'], train_enc['attention_mask'], y_train_ids)
test_dataset = TensorDataset(test_enc['input_ids'], test_enc['attention_mask'], y_test_ids)
train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=True)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE)

# Utility functions
def train_model(model, train_loader, epochs, lr=2e-5, model_name="model"):
    model.to(DEVICE)
    optimizer = AdamW(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        pbar = tqdm(train_loader, desc=f"{model_name} Epoch {epoch+1}/{epochs}", ncols=100)
        for batch in pbar:
            input_ids, attention_mask, labels = [b.to(DEVICE) for b in batch]
            optimizer.zero_grad()
            logits = model(input_ids, attention_mask=attention_mask)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            pbar.set_postfix(loss=f"{loss.item():.4f}")
        print(f"  {model_name} Avg Loss: {total_loss/len(train_loader):.4f}")

def evaluate_model(model, loader, model_name="model"):
    model.to(DEVICE)
    model.eval()
    y_pred, y_true = [], []
    with torch.no_grad():
        for batch in tqdm(loader, desc=f"Evaluating {model_name}", ncols=100):
            input_ids, attention_mask, labels = [b.to(DEVICE) for b in batch]
            logits = model(input_ids, attention_mask=attention_mask)
            preds = torch.argmax(logits, dim=-1)
            y_pred.extend(preds.cpu().tolist())
            y_true.extend(labels.cpu().tolist())
    acc = accuracy_score(y_true, y_pred)
    print(f"\n{model_name} Accuracy: {acc:.4f}")
    print(classification_report(y_true, y_pred, target_names=list(LABEL_MAP.keys())))
    return acc

# ===============================
# DistilBERT - Load pre-trained and fine-tune
# ===============================
print("\n--- Loading DistilBERT + Dense (pre-trained) ---")
distilbert_model = DistilBertDenseClassifier(num_classes=3)
model_path = os.path.join(SAVE_DIR, 'distilbert_dense.pth')
if os.path.exists(model_path):
    distilbert_model.load_state_dict(torch.load(model_path, map_location=DEVICE))
    print("Loaded existing DistilBERT weights.")
else:
    print("WARNING: distilbert_dense.pth not found. Starting from scratch.")

# Fine-tuning for 2 extra epochs
print("\n--- Fine-tuning DistilBERT (2 epochs, low LR) ---")
distilbert_model.to(DEVICE)
optimizer = AdamW(distilbert_model.parameters(), lr=5e-6)
criterion = nn.CrossEntropyLoss()
for epoch in range(2):
    distilbert_model.train()
    total_loss = 0
    for batch in tqdm(train_loader, desc=f"DistilBERT fine-tune epoch {epoch+1}", ncols=100):
        input_ids, attention_mask, labels = [b.to(DEVICE) for b in batch]
        optimizer.zero_grad()
        logits = distilbert_model(input_ids, attention_mask=attention_mask)
        loss = criterion(logits, labels)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    print(f"Fine-tune loss: {total_loss/len(train_loader):.4f}")

torch.save(distilbert_model.state_dict(), os.path.join(SAVE_DIR, 'distilbert_dense_finetuned.pth'))
distilbert_model.eval()
evaluate_model(distilbert_model, test_loader, model_name="DistilBERT (fine-tuned)")

# ===============================
# CNN + Transformer Hybrid
# ===============================
print("\n--- Training CNN + Transformer Hybrid ---")
vocab_size = tokenizer.vocab_size
cnn_transformer = CNNTransformerHybrid(vocab_size=vocab_size, embed_dim=256, num_classes=3)
train_model(cnn_transformer, train_loader, epochs=EPOCHS, lr=2e-5, model_name="CNN+Transformer")
evaluate_model(cnn_transformer, test_loader, model_name="CNN+Transformer")
torch.save(cnn_transformer.state_dict(), os.path.join(SAVE_DIR, 'cnn_transformer.pth'))

# ===============================
# Helper: get probability matrix for DL models
# ===============================
def get_dl_probs(model, loader):
    model.to(DEVICE)
    model.eval()
    all_probs = []
    with torch.no_grad():
        for batch in loader:
            input_ids, attention_mask, _ = [b.to(DEVICE) for b in batch]
            logits = model(input_ids, attention_mask=attention_mask)
            probs = torch.softmax(logits, dim=-1)
            all_probs.append(probs.cpu().numpy())
    return np.vstack(all_probs)

# ===============================
# Build probability matrices for entire test set (original)
# ===============================
# Traditional models
lr_probs_test = lr_model.predict_proba(X_test_tfidf)
rf_probs_test  = rf_model.predict_proba(X_test_tfidf)
# Reorder to match LABEL_MAP order
trad_classes = list(lr_model.classes_)
reorder_idx = [trad_classes.index(LABEL_MAP_REVERSE[i]) for i in range(3)]
lr_probs_test = lr_probs_test[:, reorder_idx]
rf_probs_test  = rf_probs_test[:, reorder_idx]

# DL models
distil_probs_test = get_dl_probs(distilbert_model, test_loader)
cnn_probs_test = get_dl_probs(cnn_transformer, test_loader)

# ===============================
# Create Meta-Learner Train / Test Split
# ===============================
print("\n--- Preparing Meta-Learner ---")
# We split the original test set into meta_train (50%) and meta_test (50%)
X_meta, X_eval, y_meta, y_eval = train_test_split(
    X_test, y_test, test_size=0.5, random_state=42, stratify=y_test
)

# Re-tokenize and re-compute probabilities for the meta subsets
def get_tokenized_loader(texts, labels, batch_size=BATCH_SIZE):
    enc = tokenize_batch(texts.tolist())
    ids = torch.tensor([LABEL_MAP[l] for l in labels])
    ds = TensorDataset(enc['input_ids'], enc['attention_mask'], ids)
    return DataLoader(ds, batch_size=batch_size)

meta_train_loader = get_tokenized_loader(X_meta, y_meta)
meta_test_loader = get_tokenized_loader(X_eval, y_eval)

# TF-IDF
X_meta_tfidf = tfidf.transform(X_meta)
X_eval_tfidf = tfidf.transform(X_eval)

# Probabilities for meta_train
lr_meta = lr_model.predict_proba(X_meta_tfidf)[:, reorder_idx]
rf_meta  = rf_model.predict_proba(X_meta_tfidf)[:, reorder_idx]
distil_meta = get_dl_probs(distilbert_model, meta_train_loader)
cnn_meta = get_dl_probs(cnn_transformer, meta_train_loader)

# Probabilities for meta_test
lr_eval = lr_model.predict_proba(X_eval_tfidf)[:, reorder_idx]
rf_eval  = rf_model.predict_proba(X_eval_tfidf)[:, reorder_idx]
distil_eval = get_dl_probs(distilbert_model, meta_test_loader)
cnn_eval = get_dl_probs(cnn_transformer, meta_test_loader)

# Build stacking features (12 dimensions)
X_meta_features = np.hstack([lr_meta, rf_meta,  distil_meta, cnn_meta])
X_eval_features = np.hstack([lr_eval, rf_eval,  distil_eval, cnn_eval])

y_meta_ids = [LABEL_MAP[l] for l in y_meta]
y_eval_ids = [LABEL_MAP[l] for l in y_eval]

# Train XGBoost meta-learner
print("Training XGBoost meta-learner...")
meta_model = XGBClassifier(
    n_estimators=100,
    max_depth=3,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric='mlogloss',
    random_state=42
)
meta_model.fit(X_meta_features, y_meta_ids)

# Encode labels for safety
le = LabelEncoder()
le.fit(y_meta)   # classes will be 'ham','phishing','spam' in alphabetical? We'll store mapping.
# To be absolutely consistent, we save a dict mapping integer -> label as in app.py
label_to_id = LABEL_MAP
id_to_label = LABEL_MAP_REVERSE

# Evaluate meta-learner
meta_preds = meta_model.predict(X_eval_features)
meta_acc = accuracy_score(y_eval_ids, meta_preds)
print(f"\nMeta-Learner Accuracy: {meta_acc:.4f}")
print(classification_report(y_eval_ids, meta_preds, target_names=list(LABEL_MAP.keys())))

# Compare with old weighted ensemble on the same eval set
weights = {'lr': 0.15, 'rf': 0.15, 'distilbert': 0.40, 'cnn_transformer': 0.30}
weighted_probs = (weights['lr'] * lr_eval + weights['rf'] * rf_eval +
                  weights['distilbert'] * distil_eval + weights['cnn_transformer'] * cnn_eval)
weighted_preds = np.argmax(weighted_probs, axis=1)
weighted_acc = accuracy_score(y_eval_ids, weighted_preds)
print(f"Old Weighted Ensemble Accuracy: {weighted_acc:.4f}")

# Save meta-learner and mapping
joblib.dump(meta_model, os.path.join(SAVE_DIR, 'meta_learner.pkl'))
joblib.dump(label_to_id, os.path.join(SAVE_DIR, 'meta_label_encoder.pkl'))  # app.py expects a .pkl with a dict-like mapping
print("[OK]  Meta-learner saved.")

# ===============================
# Save ensemble config (still useful for fallback)
# ===============================
ensemble_config = {
    'weights': weights,
    'label_map': LABEL_MAP,
    'label_map_reverse': LABEL_MAP_REVERSE,
    'trad_class_order': trad_classes,
    'reorder_idx': reorder_idx,
    'max_len': MAX_LEN,
    'vocab_size': vocab_size,
}
joblib.dump(ensemble_config, os.path.join(SAVE_DIR, 'ensemble_config.pkl'))

# ===============================
# LIME explanation (sample)
# ===============================
print("\n--- Generating LIME sample ---")
from lime.lime_text import LimeTextExplainer
lime_explainer = LimeTextExplainer(class_names=list(LABEL_MAP.keys()))
def lime_predict_fn(texts):
    vecs = tfidf.transform(texts)
    probs = lr_model.predict_proba(vecs)
    return probs[:, reorder_idx]

for label_name in list(LABEL_MAP.keys()):
    sample = X_test[y_test == label_name].iloc[0]
    exp = lime_explainer.explain_instance(sample, lime_predict_fn, num_features=10, num_samples=500)
    exp.save_to_file(os.path.join(SAVE_DIR, f'lime_explanation_{label_name}.html'))

print("\n--- All training complete ---")
print(f"Models saved to: {os.path.abspath(SAVE_DIR)}")