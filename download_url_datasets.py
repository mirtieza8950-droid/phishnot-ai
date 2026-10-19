"""
Download and merge phishing URL datasets from HuggingFace (2024-2025 sources).

Sources:
  1. Razvan27/remla_phishing_url    - 1.93M URLs, "phishing"/"legitimate" labels
  2. kmack/Phishing_urls            - 708k URLs, binary 0/1, most downloaded
  3. EustassKidman/malicious-url    - 641k URLs, multi-class Sep 2024 (filter phishing+benign)

Output: datasets/url_data_combined.csv  (columns: url, label)
        label: 0 = legitimate, 1 = phishing
        Balanced to MAX_PER_CLASS per class (default 100 000).

Run:
    pip install datasets pandas scikit-learn
    python download_url_datasets.py
"""

import os

# ── Redirect caches to D: before any HuggingFace import ─────────────────────
_CACHE = os.environ.get("HF_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "phishnot"))
os.makedirs(os.path.join(_CACHE, "hub"), exist_ok=True)
os.environ.setdefault("HF_HOME",            os.path.join(_CACHE, "hub"))
os.environ.setdefault("HF_HUB_CACHE",       os.path.join(_CACHE, "hub"))
os.environ.setdefault("TRANSFORMERS_CACHE", os.path.join(_CACHE, "hub"))
# ─────────────────────────────────────────────────────────────────────────────

import pandas as pd
from sklearn.utils import resample

os.makedirs("datasets", exist_ok=True)

MAX_PER_CLASS = 100_000   # cap per class - 3.3M -> manageable 200k
RANDOM_STATE  = 42
OUT_PATH      = os.path.join("datasets", "url_data_combined.csv")


def _validate_url(url) -> bool:
    if not isinstance(url, str):
        return False
    url = url.strip()
    return len(url) >= 8 and len(url) <= 2048


# ── Source 1: Razvan27/remla_phishing_url ────────────────────────────────────

def load_razvan27() -> pd.DataFrame:
    """1.93M URLs - "phishing" / "legitimate" string labels, 'url' column."""
    print("Downloading Razvan27/remla_phishing_url ...")
    from datasets import load_dataset
    rows = []
    for split in ("train", "validation", "test"):
        try:
            ds = load_dataset("Razvan27/remla_phishing_url", split=split)
            df = ds.to_pandas()
            url_col   = "url"
            label_col = "label"
            for _, row in df.iterrows():
                url = str(row.get(url_col, "")).strip()
                if not _validate_url(url):
                    continue
                raw = str(row.get(label_col, "")).strip().lower()
                if raw == "phishing":
                    label = 1
                elif raw in ("legitimate", "benign"):
                    label = 0
                else:
                    continue
                rows.append({"url": url, "label": label})
        except Exception as e:
            print(f"  WARNING: Razvan27 split '{split}' failed - {e}")

    result = pd.DataFrame(rows)
    counts = result["label"].value_counts().to_dict() if not result.empty else {}
    print(f"  Razvan27 loaded: {len(result)} rows  {counts}")
    return result


# ── Source 2: kmack/Phishing_urls ────────────────────────────────────────────

def load_kmack() -> pd.DataFrame:
    """708k URLs - int labels 0/1, 'text' column (URL string)."""
    print("Downloading kmack/Phishing_urls ...")
    from datasets import load_dataset
    rows = []
    for split in ("train", "test", "valid"):
        try:
            ds = load_dataset("kmack/Phishing_urls", split=split)
            df = ds.to_pandas()
            for _, row in df.iterrows():
                url = str(row.get("text", "")).strip()
                if not _validate_url(url):
                    continue
                try:
                    label = int(row.get("label", -1))
                except (ValueError, TypeError):
                    continue
                if label not in (0, 1):
                    continue
                rows.append({"url": url, "label": label})
        except Exception as e:
            print(f"  WARNING: kmack split '{split}' failed - {e}")

    result = pd.DataFrame(rows)
    counts = result["label"].value_counts().to_dict() if not result.empty else {}
    print(f"  kmack loaded: {len(result)} rows  {counts}")
    return result


# ── Source 3: EustassKidman/malicious-url (Sep 2024) ─────────────────────────

def load_eustass() -> pd.DataFrame:
    """
    641k URLs - multi-class; keep only type_code 0 (benign) and 3 (phishing).
    'url' column, 'type_code' int column.
    """
    print("Downloading EustassKidman/malicious-url ...")
    from datasets import load_dataset
    rows = []
    for split in ("train", "val", "test"):
        try:
            ds = load_dataset("EustassKidman/malicious-url", split=split)
            df = ds.to_pandas()
            for _, row in df.iterrows():
                url = str(row.get("url", "")).strip()
                if not _validate_url(url):
                    continue
                try:
                    type_code = int(row.get("type_code", -1))
                except (ValueError, TypeError):
                    # Fall back to string 'type' column
                    t = str(row.get("type", "")).strip().lower()
                    if t == "benign":
                        type_code = 0
                    elif t == "phishing":
                        type_code = 3
                    else:
                        continue
                if type_code == 0:
                    label = 0
                elif type_code == 3:
                    label = 1
                else:
                    continue   # skip defacement / malware
                rows.append({"url": url, "label": label})
        except Exception as e:
            print(f"  WARNING: EustassKidman split '{split}' failed - {e}")

    result = pd.DataFrame(rows)
    counts = result["label"].value_counts().to_dict() if not result.empty else {}
    print(f"  EustassKidman loaded: {len(result)} rows  {counts}")
    return result


# ── Balance ───────────────────────────────────────────────────────────────────

def balance(df: pd.DataFrame, max_per_class: int) -> pd.DataFrame:
    parts = []
    for label_val, group in df.groupby("label"):
        if len(group) > max_per_class:
            group = resample(group, replace=False, n_samples=max_per_class,
                             random_state=RANDOM_STATE)
        parts.append(group)
    return pd.concat(parts, ignore_index=True).sample(
        frac=1, random_state=RANDOM_STATE
    ).reset_index(drop=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    frames = []

    for loader, name in [
        (load_razvan27, "Razvan27"),
        (load_kmack,    "kmack"),
        (load_eustass,  "EustassKidman"),
    ]:
        try:
            df = loader()
            if not df.empty:
                frames.append(df)
        except Exception as e:
            print(f"WARNING: {name} failed entirely - {e}")

    if not frames:
        print("ERROR: No datasets loaded. Install `datasets` and retry.")
        return

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.drop_duplicates(subset=["url"])
    combined = combined[combined["url"].apply(_validate_url)]
    combined = combined[combined["label"].isin([0, 1])]

    print(f"\nCombined (before balance): {len(combined)} rows")
    print(combined["label"].value_counts().rename({0: "legitimate", 1: "phishing"}).to_string())

    balanced = balance(combined, MAX_PER_CLASS)

    print(f"\nFinal balanced dataset: {len(balanced)} rows")
    print(balanced["label"].value_counts().rename({0: "legitimate", 1: "phishing"}).to_string())

    balanced.to_csv(OUT_PATH, index=False)
    print(f"\nSaved -> {OUT_PATH}")
    print("Next step: run  python train_url_model.py  to retrain the URL model.")


if __name__ == "__main__":
    main()
