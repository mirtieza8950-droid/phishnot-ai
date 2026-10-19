"""
train_lora_adapters.py — LoRA fine-tuning for DeBERTa-v3-small and DistilRoBERTa.

Uses PEFT to inject low-rank adapters (rank=8) into query/value projections.
Only trains ~0.3M params per model instead of full 83M. Monthly self-learning.

Outputs:
  models/deberta_lora/           (adapter weights + config)
  models/distilroberta_lora/     (adapter weights + config)

Usage:
  python train_lora_adapters.py                     # full fine-tune on feedback
  python train_lora_adapters.py --epochs 3          # custom epochs
  python train_lora_adapters.py --max-samples 500   # limit training data
  python train_lora_adapters.py --min-trust 0.85    # stricter trust filter
"""
import os
import sys
import time
import shutil
import argparse

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from transformers import get_linear_schedule_with_warmup
from peft import LoraConfig, get_peft_model, TaskType
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

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
parser.add_argument("--epochs", type=int, default=2)
parser.add_argument("--batch-size", type=int, default=16)
parser.add_argument("--max-samples", type=int, default=1000,
                    help="Maximum feedback samples to use")
parser.add_argument("--max-len", type=int, default=128)
parser.add_argument("--min-trust", type=float, default=0.8,
                    help="Minimum trust score for feedback inclusion")
parser.add_argument("--min-consensus", type=int, default=3,
                    help="Minimum consensus count for feedback inclusion")
parser.add_argument("--lr", type=float, default=2e-5)
args = parser.parse_args()

MODELS_DIR = "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
NUM_CLASSES = 3
LABELS = ['ham', 'spam', 'phishing']

print(f"Device: {DEVICE}")
print(f"LoRA config: rank=8, alpha=16, target=[query,value], dropout=0.1")


# ── Load data ──────────────────────────────────────────────────────────────────
print("\nLoading training data...")

# Base validation data
val_path = "validation_data.csv"
base_texts, base_labels = [], []
if os.path.exists(val_path):
    val_df = pd.read_csv(val_path)
    base_texts = val_df["clean_text"].fillna("").tolist()
    base_labels = val_df["label"].tolist()
    print(f"  Base validation: {len(base_texts)} samples")

# Confirmed feedback corrections
feedback_texts, feedback_labels, feedback_weights = [], [], []
try:
    from app.services.self_training_pipeline import get_confirmed_corrections
    corrections = get_confirmed_corrections(
        min_consensus=args.min_consensus,
        min_trust=args.min_trust,
    )
    feedback_texts = [c["input_text"] for c in corrections]
    feedback_labels = [c["user_label"] for c in corrections]
    feedback_weights = [c["trust_score"] for c in corrections]
    print(f"  Feedback corrections: {len(feedback_texts)} samples")
except Exception as e:
    print(f"  [WARN] Could not load feedback: {e}")

all_texts = base_texts + feedback_texts
all_labels = base_labels + feedback_labels
all_weights = [1.0] * len(base_texts) + feedback_weights

# Cap at max_samples
if len(all_texts) > args.max_samples:
    rng = np.random.RandomState(42)
    idx = rng.choice(len(all_texts), args.max_samples, replace=False)
    all_texts = [all_texts[i] for i in idx]
    all_labels = [all_labels[i] for i in idx]
    all_weights = [all_weights[i] for i in idx]
    print(f"  Capped to {args.max_samples} samples")

if len(all_texts) < 50:
    print("[ERROR] Not enough data for LoRA training (need >= 50 samples)")
    sys.exit(1)

print(f"  Total: {len(all_texts)} samples")

le = LabelEncoder()
y_all = le.fit_transform(all_labels)
sample_weights = np.array(all_weights)


# ── Helper: train one LoRA model ──────────────────────────────────────────────

def train_lora_for_model(model_name, base_model_cls, tokenizer_cls, save_dir):
    """Train LoRA adapters for one transformer model."""
    print(f"\n{'='*60}")
    print(f"Training LoRA adapters for {model_name}")
    print(f"{'='*60}")

    t0 = time.time()

    # Load base tokenizer
    tok_path = os.path.join(MODELS_DIR, f"{model_name}_tokenizer")
    if os.path.isdir(tok_path):
        tokenizer = tokenizer_cls.from_pretrained(tok_path)
    else:
        tokenizer = tokenizer_cls.from_pretrained(
            'microsoft/deberta-v3-small' if 'deberta' in model_name else 'distilroberta-base'
        )

    # Load base model
    base_model = base_model_cls(num_classes=NUM_CLASSES)
    weight_path = os.path.join(MODELS_DIR,
                               f"{model_name}.pth" if os.path.exists(
                                   os.path.join(MODELS_DIR, f"{model_name}.pth")
                               ) else f"{model_name}_dense.pth")
    if os.path.exists(weight_path):
        base_model.load_state_dict(torch.load(weight_path, map_location=DEVICE))
        print(f"  Loaded base weights from {weight_path}")
    else:
        print(f"  [WARN] Base weights not found at {weight_path}, training from scratch")

    base_model.to(DEVICE)

    # ── Apply LoRA ────────────────────────────────────────────────────────────
    # We apply LoRA to the transformer backbone's query and value projections
    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=8,
        lora_alpha=16,
        target_modules=["query", "value"],
        lora_dropout=0.1,
        bias="none",
        num_labels=NUM_CLASSES,
    )

    # Wrap the base model so PEFT can find the transformer
    class TransformerWrapper(nn.Module):
        """Unwrap the classifier head to expose the transformer backbone for PEFT."""
        def __init__(self, model):
            super().__init__()
            self.model = model

        def forward(self, input_ids, attention_mask=None, **kwargs):
            return self.model(input_ids, attention_mask)

    wrapper = TransformerWrapper(base_model)

    # For DeBERTa, the backbone is model.deberta; for DistilRoBERTa it's model.roberta
    if hasattr(base_model, 'deberta'):
        backbone = base_model.deberta
    elif hasattr(base_model, 'roberta'):
        backbone = base_model.roberta
    else:
        raise ValueError(f"Unknown model structure for {model_name}")

    lora_model = get_peft_model(backbone, lora_config)
    lora_model.print_trainable_parameters()
    lora_model.to(DEVICE)

    # ── Tokenize ──────────────────────────────────────────────────────────────
    print("  Tokenizing...")
    encodings = tokenizer(
        all_texts,
        padding='max_length',
        truncation=True,
        max_length=args.max_len,
        return_tensors='pt',
    )

    # ── Train/test split ──────────────────────────────────────────────────────
    X_ids = encodings['input_ids']
    X_mask = encodings['attention_mask']

    X_ids_tr, X_ids_te, X_mask_tr, X_mask_te, y_tr, y_te, w_tr, _ = train_test_split(
        X_ids, X_mask, y_all, sample_weights,
        test_size=0.15, random_state=42, stratify=y_all
    )

    train_ds = TensorDataset(X_ids_tr, X_mask_tr, torch.tensor(y_tr), torch.tensor(w_tr))
    train_dl = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    test_ds = TensorDataset(X_ids_te, X_mask_te, torch.tensor(y_te))
    test_dl = DataLoader(test_ds, batch_size=args.batch_size)

    # ── Train ─────────────────────────────────────────────────────────────────
    optimizer = torch.optim.AdamW(lora_model.parameters(), lr=args.lr, weight_decay=0.01)
    total_steps = len(train_dl) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps
    )

    # Class weights for imbalanced data
    class_counts = np.bincount(y_all, minlength=NUM_CLASSES)
    class_weights = torch.tensor(
        [len(all_texts) / (NUM_CLASSES * max(c, 1)) for c in class_counts],
        dtype=torch.float
    ).to(DEVICE)

    best_accuracy = 0.0

    for epoch in range(args.epochs):
        lora_model.train()
        epoch_loss = 0.0
        n_batches = 0

        for batch_idx, (ids, mask, labels, weights) in enumerate(train_dl):
            ids = ids.to(DEVICE)
            mask = mask.to(DEVICE)
            labels = labels.to(DEVICE)
            weights = weights.to(DEVICE)

            logits = lora_model(input_ids=ids, attention_mask=mask)

            # Weighted cross-entropy
            loss = nn.functional.cross_entropy(logits, labels, weight=class_weights)
            # Scale loss by individual sample weights
            loss = (loss * weights).mean()

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(lora_model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            epoch_loss += loss.item()
            n_batches += 1

            if batch_idx % 20 == 0:
                print(f"    Batch {batch_idx}/{len(train_dl)} | Loss: {loss.item():.4f}")

        avg_loss = epoch_loss / max(n_batches, 1)

        # ── Evaluate ──────────────────────────────────────────────────────────
        lora_model.eval()
        all_preds, all_true = [], []
        with torch.no_grad():
            for ids, mask, labels in test_dl:
                ids = ids.to(DEVICE)
                mask = mask.to(DEVICE)
                logits = lora_model(input_ids=ids, attention_mask=mask)
                preds = logits.argmax(dim=-1).cpu().numpy()
                all_preds.extend(preds)
                all_true.extend(labels.numpy())

        accuracy = accuracy_score(all_true, all_preds)
        print(f"  Epoch {epoch+1}/{args.epochs} | Loss: {avg_loss:.4f} | "
              f"Accuracy: {accuracy:.4f}")

        if accuracy > best_accuracy:
            best_accuracy = accuracy
            # Save best
            lora_model.save_pretrained(save_dir)
            print(f"    -> Saved best model (accuracy={accuracy:.4f})")

    elapsed = time.time() - t0
    print(f"\n  [{model_name}] LoRA training complete in {elapsed:.1f}s")
    print(f"  Best accuracy: {best_accuracy:.4f}")
    print(f"  Adapters saved to: {save_dir}")

    return best_accuracy


# ── Train LoRA for both models ────────────────────────────────────────────────

from app.services.ensemble_engine import DeBertaDenseClassifier, DistilRobertaDenseClassifier
from transformers import DebertaV2Tokenizer, RobertaTokenizer

results = {}

results['deberta'] = train_lora_for_model(
    model_name='deberta',
    base_model_cls=DeBertaDenseClassifier,
    tokenizer_cls=DebertaV2Tokenizer,
    save_dir=os.path.join(MODELS_DIR, 'deberta_lora'),
)

results['distilroberta'] = train_lora_for_model(
    model_name='distilroberta',
    base_model_cls=DistilRobertaDenseClassifier,
    tokenizer_cls=RobertaTokenizer,
    save_dir=os.path.join(MODELS_DIR, 'distilroberta_lora'),
)

# ── Summary ────────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("LoRA Training Summary")
print(f"{'='*60}")
print(f"  DeBERTa LoRA:  {results['deberta']:.4f}")
print(f"  DistilRoBERTa LoRA: {results['distilroberta']:.4f}")
print(f"  Training data: {len(all_texts)} samples "
      f"({len(base_texts)} base + {len(feedback_texts)} feedback)")
print(f"  LoRA rank=8, alpha=16, ~0.3M params per model")
print(f"\nModels saved to:")
print(f"  {MODELS_DIR}/deberta_lora/")
print(f"  {MODELS_DIR}/distilroberta_lora/")
