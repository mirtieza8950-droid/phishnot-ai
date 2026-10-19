"""
Train DeBERTa-v3-small only, then rebuild ensemble_config.pkl.

Loads existing LR / RF / TF-IDF / DistilRoBERTa from disk - nothing else
is retrained. After training, runs a full ensemble evaluation with all four
models so the classification report reflects the real current state.

Usage:
    python train_deberta_only.py              # 4 epochs (default)
    python train_deberta_only.py --epochs 2   # quick sanity check
    python train_deberta_only.py --max-samples 20000  # fast smoke test

Requirements that must exist before running:
    models/tfidf_vectorizer.pkl
    models/logistic_regression.pkl
    models/rf_model.pkl
    models/distilroberta.pth
    models/distilroberta_tokenizer/  (or falls back to HuggingFace)
    final_data_balanced.csv
"""

import os
import sys
import argparse

# ── Redirect all caches to D: before any HuggingFace import ──────────────────
_CACHE = os.environ.get("HF_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "phishnot"))
os.makedirs(os.path.join(_CACHE, "hub"), exist_ok=True)
os.makedirs(os.path.join(_CACHE, "torch"), exist_ok=True)
os.environ.setdefault("HF_HOME",            os.environ.get("HF_HOME", _CACHE))
os.environ.setdefault("HF_HUB_CACHE",       os.path.join(_CACHE, "hub"))
os.environ.setdefault("TRANSFORMERS_CACHE", os.path.join(_CACHE, "hub"))
os.environ.setdefault("TORCH_HOME",         os.path.join(_CACHE, "torch"))
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")   # suppress pre-training head warnings
# ─────────────────────────────────────────────────────────────────────────────

import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from torch.optim import AdamW
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from transformers import (
    DebertaV2Tokenizer, DebertaV2Model,
    RobertaTokenizer, RobertaModel,
    get_linear_schedule_with_warmup,
)
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

# ── Progress tracking (for GUI) ──────────────────────────────────────────────
from train_progress import (
    write_progress, read_control, clear_control, wait_if_paused,
    check_stop, epoch_description_deberta
)

# ── CLI args ──────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--epochs",      type=int, default=4,
                    help="Number of fine-tuning epochs (default 4)")
parser.add_argument("--max-samples", type=int, default=None,
                    help="Cap training set size for a quick smoke-test run")
parser.add_argument("--batch-size",  type=int, default=16)
parser.add_argument("--lr",          type=float, default=2e-5)
parser.add_argument("--max-len",     type=int, default=256,
                    help="Token length. 128 is ~2x faster and covers most emails.")
parser.add_argument("--fp16",        action="store_true",
                    help="Mixed-precision training - 1.5-2x faster on CUDA, no accuracy loss.")
args = parser.parse_args()

EPOCHS      = args.epochs
MAX_SAMPLES = args.max_samples
BATCH_SIZE  = args.batch_size
LR          = args.lr
MAX_LEN     = args.max_len
SAVE_DIR    = "models"

LABEL_MAP         = {'ham': 0, 'phishing': 1, 'spam': 2}
LABEL_MAP_REVERSE = {v: k for k, v in LABEL_MAP.items()}

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
USE_FP16 = args.fp16 and DEVICE.type == "cuda"
print(f"Device : {DEVICE}")
if DEVICE.type == "cuda":
    print(f"GPU    : {torch.cuda.get_device_name(0)}")
    print(f"VRAM   : {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
print(f"Epochs : {EPOCHS}  |  Batch: {BATCH_SIZE}  |  LR: {LR}  |  MaxLen: {MAX_LEN}  |  fp16: {USE_FP16}")


# ── Guard: check required files exist ─────────────────────────────────────────
_required = [
    os.path.join(SAVE_DIR, "tfidf_vectorizer.pkl"),
    os.path.join(SAVE_DIR, "logistic_regression.pkl"),
    os.path.join(SAVE_DIR, "rf_model.pkl"),
    os.path.join(SAVE_DIR, "distilroberta.pth"),
    "final_data_balanced.csv",
]
_missing = [p for p in _required if not os.path.exists(p)]
if _missing:
    print("\nMissing required files:")
    for p in _missing:
        print(f"  {p}")
    raise SystemExit("Run training.py at least once first to produce these files.")


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


# ── Load data ─────────────────────────────────────────────────────────────────
print("\nLoading dataset...")
df = pd.read_csv("final_data_balanced.csv")
X  = df["clean_text"].fillna("")
y  = df["label"]

# Use the SAME split as training.py so test sets are comparable
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

if MAX_SAMPLES and len(X_train) > MAX_SAMPLES:
    X_train = X_train.sample(n=MAX_SAMPLES, random_state=42)
    y_train = y_train.loc[X_train.index]
    print(f"Training set capped at {MAX_SAMPLES} samples.")

print(f"Train: {len(X_train)}  |  Test: {len(X_test)}")


# ── Load existing classical models ────────────────────────────────────────────
print("\nLoading existing models from disk...")
tfidf    = joblib.load(os.path.join(SAVE_DIR, "tfidf_vectorizer.pkl"))
lr_model = joblib.load(os.path.join(SAVE_DIR, "logistic_regression.pkl"))
rf_model = joblib.load(os.path.join(SAVE_DIR, "rf_model.pkl"))
print("  LR / RF / TF-IDF loaded.")

X_test_tfidf = tfidf.transform(X_test)
trad_classes = list(lr_model.classes_)
reorder_idx  = [trad_classes.index(LABEL_MAP_REVERSE[i]) for i in range(3)]


# ── Tokenize for DeBERTa ──────────────────────────────────────────────────────
print("\nTokenizing for DeBERTa-v3-small...")
deberta_tokenizer = DebertaV2Tokenizer.from_pretrained('microsoft/deberta-v3-small')

deberta_train_enc = deberta_tokenizer(
    X_train.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)
deberta_test_enc = deberta_tokenizer(
    X_test.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)

y_train_t = torch.tensor([LABEL_MAP[l] for l in y_train])
y_test_t  = torch.tensor([LABEL_MAP[l] for l in y_test])

train_loader = DataLoader(
    TensorDataset(deberta_train_enc['input_ids'],
                  deberta_train_enc['attention_mask'],
                  y_train_t),
    batch_size=BATCH_SIZE, shuffle=True, drop_last=True,
)
test_loader = DataLoader(
    TensorDataset(deberta_test_enc['input_ids'],
                  deberta_test_enc['attention_mask'],
                  y_test_t),
    batch_size=BATCH_SIZE,
)


# ── Train DeBERTa ─────────────────────────────────────────────────────────────
print(f"\n--- Training DeBERTa-v3-small ({EPOCHS} epochs) ---")

# ── Fail-safe checkpoint/resume helpers ──────────────────────────────────────
_save_path   = os.path.join(SAVE_DIR, "deberta_dense.pth")
_resume_path = os.path.join(SAVE_DIR, "deberta_dense_resume.pt")
_CHECKPOINT_EVERY = max(1, len(train_loader) // 6)   # ~6 saves per epoch

def _save_resume(epoch, completed, batch=0):
    ckpt = {
        'model':           deberta_model.state_dict(),
        'optimizer':       optimizer.state_dict(),
        'scheduler':       scheduler.state_dict(),
        'scaler':          scaler.state_dict(),
        'epoch':           epoch,
        'batch':           batch,              # absolute batch index inside epoch
        'epoch_completed': completed,
    }
    tmp = _resume_path + ".tmp"
    torch.save(ckpt, tmp)
    os.replace(tmp, _resume_path)

def _save_plain(path):
    tmp = path + ".tmp"
    torch.save(deberta_model.state_dict(), tmp)
    os.replace(tmp, path)

deberta_model = DeBertaDenseClassifier(num_classes=3)

optimizer    = AdamW(deberta_model.parameters(), lr=LR)
criterion    = nn.CrossEntropyLoss()
total_steps  = len(train_loader) * EPOCHS
warmup_steps = max(1, total_steps // 10)
scheduler    = get_linear_schedule_with_warmup(
    optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps
)

# fp16 scaler - no-op when USE_FP16 is False (CPU or user didn't pass --fp16)
scaler = torch.cuda.amp.GradScaler(enabled=USE_FP16)

# Persist the tokenizer immediately so an interrupted run keeps it.
deberta_tokenizer.save_pretrained(os.path.join(SAVE_DIR, "deberta_tokenizer"))

# ── Resume from a previous interrupted run if present ────────────────────────
start_epoch  = 0
resume_batch = 0
if os.path.exists(_resume_path):
    ckpt = torch.load(_resume_path, map_location=DEVICE)
    deberta_model.load_state_dict(ckpt['model'])
    optimizer.load_state_dict(ckpt['optimizer'])
    scheduler.load_state_dict(ckpt['scheduler'])
    scaler.load_state_dict(ckpt['scaler'])
    if ckpt.get('epoch_completed'):
        start_epoch  = ckpt['epoch'] + 1
        resume_batch = 0
    else:
        start_epoch  = ckpt['epoch']
        resume_batch = ckpt.get('batch', 0)
    print(f"[RESUME] Continuing epoch {min(start_epoch + 1, EPOCHS)}/{EPOCHS} "
          f"at batch {resume_batch + 1}/{len(train_loader)}.")

deberta_model.to(DEVICE)

for epoch in range(start_epoch, EPOCHS):
    # Deterministic per-epoch shuffle -> resumed batch order is identical to the
    # interrupted run, so we can skip straight to the exact batch we died at.
    torch.manual_seed(1337 + epoch)
    epoch_loader = iter(train_loader)
    skip = resume_batch if epoch == start_epoch else 0
    for _ in range(skip):
        next(epoch_loader)
    resume_batch = 0

    deberta_model.train()
    total_loss = 0
    
    # Print epoch description for PhishNot context
    epoch_desc = epoch_description_deberta(epoch, EPOCHS)
    print(f"  [INFO] {epoch_desc}")
    
    pbar = tqdm(epoch_loader, total=len(train_loader) - skip,
                desc=f"DeBERTa Epoch {epoch+1}/{EPOCHS}",
                ncols=100)
    for batch_idx, batch in enumerate(pbar, 1):
        # Check for pause/stop from GUI
        if check_stop():
            _save_resume(epoch, completed=False, batch=batch_idx + skip)
            write_progress("deberta", epoch, EPOCHS, batch_idx + skip, len(train_loader),
                          loss.item(), status="stopped")
            sys.exit(0)
        if read_control() == 'pause':
            _save_resume(epoch, completed=False, batch=batch_idx + skip)
            write_progress("deberta", epoch, EPOCHS, batch_idx + skip, len(train_loader),
                          loss.item(), status="paused")
            if wait_if_paused():
                _save_resume(epoch, completed=False, batch=batch_idx + skip)
                write_progress("deberta", epoch, EPOCHS, batch_idx + skip, len(train_loader),
                              loss.item(), status="stopped")
                sys.exit(0)
            write_progress("deberta", epoch, EPOCHS, batch_idx + skip, len(train_loader),
                          loss.item(), status="training")

        input_ids, attention_mask, labels = [b.to(DEVICE) for b in batch]
        optimizer.zero_grad()

        with torch.cuda.amp.autocast(enabled=USE_FP16):
            logits = deberta_model(input_ids, attention_mask=attention_mask)
            loss   = criterion(logits, labels)

        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(deberta_model.parameters(), 1.0)
        scaler.step(optimizer)
        scaler.update()
        scheduler.step()

        total_loss += loss.item()
        pbar.set_postfix(loss=f"{loss.item():.4f}")
        
        # Write progress every 10 batches for GUI (not every batch to avoid I/O overhead)
        if batch_idx % 10 == 0:
            write_progress("deberta", epoch, EPOCHS, batch_idx + skip, len(train_loader),
                          loss.item(), status="training",
                          extra={"epoch_desc": epoch_desc})

    avg_loss = total_loss / len(train_loader)
    print(f"  Epoch {epoch+1}/{EPOCHS} - Avg Loss: {avg_loss:.4f}")
    _save_plain(_save_path)
    _save_resume(epoch, completed=True)
    write_progress("deberta", epoch, EPOCHS, len(train_loader), len(train_loader),
                  avg_loss, status="epoch_complete",
                  extra={"epoch_desc": epoch_desc, "avg_loss": avg_loss})
    print(f"  [OK]  Checkpoint saved -> {_save_path}  (safe to stop here)")

deberta_tokenizer.save_pretrained(os.path.join(SAVE_DIR, "deberta_tokenizer"))
print("DeBERTa tokenizer saved.")


# ── Evaluate DeBERTa standalone ───────────────────────────────────────────────
print("\n--- DeBERTa standalone evaluation ---")
deberta_model.eval()
db_pred_labels, db_true_labels = [], []
with torch.no_grad():
    for batch in tqdm(test_loader, desc="Evaluating DeBERTa", ncols=100):
        ids, mask, labs = [b.to(DEVICE) for b in batch]
        preds = torch.argmax(deberta_model(ids, mask), dim=-1)
        db_pred_labels.extend(preds.cpu().tolist())
        db_true_labels.extend(labs.cpu().tolist())

print(f"DeBERTa Accuracy: {accuracy_score(db_true_labels, db_pred_labels):.4f}")
print(classification_report(db_true_labels, db_pred_labels,
                             target_names=list(LABEL_MAP.keys())))


# ── Load DistilRoBERTa from disk ──────────────────────────────────────────────
print("\nLoading DistilRoBERTa from disk for ensemble eval...")
dr_tok_path = os.path.join(SAVE_DIR, "distilroberta_tokenizer")
if os.path.isdir(dr_tok_path):
    dr_tokenizer = RobertaTokenizer.from_pretrained(dr_tok_path)
else:
    dr_tokenizer = RobertaTokenizer.from_pretrained("distilroberta-base")

distilroberta_model = DistilRobertaDenseClassifier(num_classes=3)
distilroberta_model.load_state_dict(
    torch.load(os.path.join(SAVE_DIR, "distilroberta.pth"), map_location=DEVICE)
)
distilroberta_model.to(DEVICE).eval()
print("  DistilRoBERTa loaded.")

# Tokenize test set for DistilRoBERTa
dr_test_enc = dr_tokenizer(
    X_test.tolist(), padding='max_length', truncation=True,
    max_length=MAX_LEN, return_tensors='pt'
)
dr_test_loader = DataLoader(
    TensorDataset(dr_test_enc['input_ids'],
                  dr_test_enc['attention_mask'],
                  y_test_t),
    batch_size=BATCH_SIZE,
)


# ── Collect all model probabilities ──────────────────────────────────────────
def collect_probs(model, loader, name):
    model.eval()
    all_p = []
    with torch.no_grad():
        for batch in tqdm(loader, desc=f"Probs: {name}", ncols=100):
            ids, mask, _ = [b.to(DEVICE) for b in batch]
            p = torch.softmax(model(ids, mask), dim=-1)
            all_p.append(p.cpu().numpy())
    return np.vstack(all_p)


lr_probs = lr_model.predict_proba(X_test_tfidf)[:, reorder_idx]
rf_probs = rf_model.predict_proba(X_test_tfidf)[:, reorder_idx]
db_probs = collect_probs(deberta_model,       test_loader,    "DeBERTa")
dr_probs = collect_probs(distilroberta_model, dr_test_loader, "DistilRoBERTa")


# ── Ensemble evaluation ───────────────────────────────────────────────────────
W_LR, W_RF, W_DB, W_DR = 0.10, 0.15, 0.40, 0.35
ensemble_probs = W_LR * lr_probs + W_RF * rf_probs + W_DB * db_probs + W_DR * dr_probs
ensemble_preds = np.argmax(ensemble_probs, axis=1)
y_test_int     = [LABEL_MAP[l] for l in y_test]

print(f"\n--- Ensemble Evaluation (LR={W_LR} RF={W_RF} DeBERTa={W_DB} DR={W_DR}) ---")
print(f"Ensemble Accuracy: {accuracy_score(y_test_int, ensemble_preds):.4f}")
print(classification_report(y_test_int, ensemble_preds,
                             target_names=list(LABEL_MAP.keys())))


# ── Save updated ensemble_config.pkl ─────────────────────────────────────────
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
joblib.dump(ensemble_config, os.path.join(SAVE_DIR, "ensemble_config.pkl"))
print(f"\nensemble_config.pkl updated -> weights: {ensemble_config['weights']}")
print("Done. Restart the API server to load the new DeBERTa weights.")
