"""
Download, merge, and balance phishing/spam/ham email datasets from HuggingFace.

Sources pulled:
  1. puyang2025/seven-phishing-email-datasets  - 203k rows (TREC-05/06/07, CEAS-08,
                                                  Enron, SpamAssassin, Ling)
  2. ealvaradob/phishing-dataset (mails config)  - ~18k clean email bodies

Label mapping:
  - binary label=0                -> ham
  - label=1 from SpamAssassin     -> spam   (dataset_name == "Assassin")
  - label=1 from all other sources -> phishing

Output: final_data_balanced.csv  (columns: clean_text, label)
        Balanced to MAX_PER_CLASS samples per class (default 30 000).

Run:
    pip install datasets pandas scikit-learn
    python download_datasets.py
"""

import os

# ── Redirect all caches to D: before any HuggingFace import ──────────────────
_CACHE = os.environ.get("HF_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "phishnot"))
os.makedirs(os.path.join(_CACHE, "hub"), exist_ok=True)
os.environ.setdefault("HF_HOME",            os.path.join(_CACHE, "hub"))
os.environ.setdefault("HF_HUB_CACHE",       os.path.join(_CACHE, "hub"))
os.environ.setdefault("TRANSFORMERS_CACHE", os.path.join(_CACHE, "hub"))
# ─────────────────────────────────────────────────────────────────────────────

import re
import os
import pandas as pd
from sklearn.utils import resample

MAX_PER_CLASS = 30_000   # cap per class to keep training manageable
RANDOM_STATE  = 42
OUT_PATH      = "final_data_balanced.csv"


# ── Text cleaning ──────────────────────────────────────────────────────────────

_HTML_TAG    = re.compile(r'<[^>]+>')
_WHITESPACE  = re.compile(r'\s+')
_URL         = re.compile(r'https?://\S+|www\.\S+')


def clean_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = _HTML_TAG.sub(' ', text)
    text = _URL.sub(' URL ', text)
    text = _WHITESPACE.sub(' ', text).strip()
    return text[:4000]   # truncate very long bodies


# ── Dataset 1: puyang2025/seven-phishing-email-datasets ───────────────────────

def load_seven_datasets() -> pd.DataFrame:
    print("Downloading puyang2025/seven-phishing-email-datasets ...")
    from datasets import load_dataset
    ds = load_dataset("puyang2025/seven-phishing-email-datasets", split="train")
    df = ds.to_pandas()

    rows = []
    for _, row in df.iterrows():
        text = clean_text(str(row.get("text", "") or ""))
        if len(text) < 10:
            continue
        raw_label   = int(row.get("label", -1))
        source_name = str(row.get("dataset_name", "")).lower()
        if raw_label == 0:
            label = "ham"
        elif "assassin" in source_name:
            label = "spam"
        else:
            label = "phishing"
        rows.append({"clean_text": text, "label": label})

    result = pd.DataFrame(rows)
    counts = result["label"].value_counts().to_dict()
    print(f"  seven-datasets loaded: {len(result)} rows  {counts}")
    return result


# ── Dataset 2: ealvaradob/phishing-dataset (mails config) ────────────────────

def load_ealvarado() -> pd.DataFrame:
    print("Downloading ealvaradob/phishing-dataset (mails) ...")
    from datasets import load_dataset
    try:
        ds = load_dataset("ealvaradob/phishing-dataset", "mails", split="train",
                          trust_remote_code=True)
    except Exception:
        # Fallback: try without config name
        ds = load_dataset("ealvaradob/phishing-dataset", split="train",
                          trust_remote_code=True)

    df = ds.to_pandas()
    rows = []
    for _, row in df.iterrows():
        text = clean_text(str(row.get("text", "") or ""))
        if len(text) < 10:
            continue
        raw_label = int(row.get("label", -1))
        label = "phishing" if raw_label == 1 else "ham"
        rows.append({"clean_text": text, "label": label})

    result = pd.DataFrame(rows)
    counts = result["label"].value_counts().to_dict()
    print(f"  ealvarado loaded: {len(result)} rows  {counts}")
    return result


# ── Existing project data ──────────────────────────────────────────────────────

def load_existing() -> pd.DataFrame:
    frames = []
    for path in ["final_data_balanced.csv", "validation_data.csv"]:
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                if "clean_text" in df.columns and "label" in df.columns:
                    df = df[["clean_text", "label"]].dropna()
                    df["clean_text"] = df["clean_text"].apply(clean_text)
                    frames.append(df)
                    print(f"  Loaded existing: {path} ({len(df)} rows)")
            except Exception as e:
                print(f"  Skipping {path}: {e}")
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["clean_text", "label"])


# ── Balance ────────────────────────────────────────────────────────────────────

def balance(df: pd.DataFrame, max_per_class: int) -> pd.DataFrame:
    parts = []
    for label, group in df.groupby("label"):
        if len(group) > max_per_class:
            group = resample(group, replace=False, n_samples=max_per_class,
                             random_state=RANDOM_STATE)
        parts.append(group)
    result = pd.concat(parts, ignore_index=True).sample(
        frac=1, random_state=RANDOM_STATE
    ).reset_index(drop=True)
    return result


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    frames = []

    try:
        frames.append(load_seven_datasets())
    except Exception as e:
        print(f"  WARNING: seven-datasets failed ({e}). Skipping.")

    try:
        frames.append(load_ealvarado())
    except Exception as e:
        print(f"  WARNING: ealvarado failed ({e}). Skipping.")

    existing = load_existing()
    if not existing.empty:
        frames.append(existing)

    if not frames:
        print("ERROR: No datasets loaded. Install `datasets` and retry.")
        return

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.drop_duplicates(subset=["clean_text"])
    combined = combined[combined["clean_text"].str.len() >= 20]
    combined = combined[combined["label"].isin(["ham", "phishing", "spam"])]

    print(f"\nCombined (before balance): {len(combined)} rows")
    print(combined["label"].value_counts().to_string())

    balanced = balance(combined, MAX_PER_CLASS)

    print(f"\nFinal balanced dataset: {len(balanced)} rows")
    print(balanced["label"].value_counts().to_string())

    balanced.to_csv(OUT_PATH, index=False)
    print(f"\nSaved -> {OUT_PATH}")
    print("Next step: run  python training.py  to retrain all models.")


if __name__ == "__main__":
    main()
