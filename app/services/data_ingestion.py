"""
Training-data ingestion pipeline.

Sources:
  1. Phishing.Database (GitHub) - active phishing URLs, no network account needed
  2. Kaggle "taruntiwarihp/phishing-site-urls" - ~550k labeled URLs (needs kaggle creds)

Output: data/url_training_data.csv  with columns: url, label  (1=phishing, 0=legitimate)
"""
import os
import requests
import pandas as pd
from datetime import datetime, timezone
from threading import Lock

DATA_DIR = "datasets"

_PHISHING_DB_SOURCES = [
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
]

_lock  = Lock()
_state: dict = {
    "status": "idle",       # idle | running | done | error
    "started_at": None,
    "finished_at": None,
    "phishing_count": 0,
    "legitimate_count": 0,
    "total": 0,
    "sources_used": [],
    "error": None,
    "data_path": None,
}


def get_state() -> dict:
    with _lock:
        return dict(_state)


def _set(**kw):
    with _lock:
        _state.update(kw)


# ── Source fetchers ─────────────────────────────────────────────────────────────

def _fetch_phishing_db(max_urls: int) -> list[str]:
    seen: set[str] = set()
    for src in _PHISHING_DB_SOURCES:
        try:
            resp = requests.get(src, timeout=30)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                seen.add(line)
                if len(seen) >= max_urls:
                    return list(seen)
        except Exception as exc:
            print(f"[ingest] {src}: {exc}")
    return list(seen)[:max_urls]


def _load_kaggle(max_rows: int) -> pd.DataFrame | None:
    try:
        import kagglehub
        from kagglehub import KaggleDatasetAdapter
        raw = kagglehub.load_dataset(
            KaggleDatasetAdapter.PANDAS,
            "taruntiwarihp/phishing-site-urls",
            "",
        )
        raw.columns = [c.lower().strip() for c in raw.columns]
        url_col   = next((c for c in raw.columns if "url"   in c), None)
        label_col = next((c for c in raw.columns if "label" in c or "status" in c), None)
        if not url_col or not label_col:
            return None
        out = raw[[url_col, label_col]].rename(columns={url_col: "url", label_col: "raw_label"})
        out["label"] = out["raw_label"].apply(
            lambda x: 1 if str(x).lower() in ("phishing", "bad", "1") else 0
        )
        return out[["url", "label"]].dropna().sample(
            n=min(max_rows, len(out)), random_state=42
        )
    except Exception as exc:
        print(f"[ingest] Kaggle failed: {exc}")
        return None


# ── Main pipeline ───────────────────────────────────────────────────────────────

def run_ingestion(
    use_phishing_db: bool = True,
    use_kaggle: bool = True,
    max_phishing_db: int = 20_000,
    max_kaggle: int = 100_000,
) -> str:
    """Fetch, merge, and save URL training data. Runs synchronously in a background thread."""
    _set(
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
        phishing_count=0, legitimate_count=0, total=0,
        sources_used=[], error=None, data_path=None,
    )

    frames: list[pd.DataFrame] = []
    sources: list[str] = []
    errors:  list[str] = []

    if use_kaggle:
        df = _load_kaggle(max_kaggle)
        if df is not None:
            frames.append(df)
            sources.append(f"Kaggle taruntiwarihp/phishing-site-urls ({len(df):,} rows)")
        else:
            errors.append("Kaggle: load failed (check credentials in ~/.kaggle/kaggle.json)")

    if use_phishing_db:
        urls = _fetch_phishing_db(max_phishing_db)
        if urls:
            frames.append(pd.DataFrame({"url": urls, "label": 1}))
            sources.append(f"Phishing.Database/GitHub ({len(urls):,} URLs)")
        else:
            errors.append("Phishing.Database: no URLs fetched")

    if not frames:
        msg = "No data from any source. " + " | ".join(errors)
        _set(status="error", error=msg,
             finished_at=datetime.now(timezone.utc).isoformat())
        raise RuntimeError(msg)

    combined = (
        pd.concat(frames, ignore_index=True)
        .drop_duplicates("url")
        .dropna(subset=["url", "label"])
        .reset_index(drop=True)
    )

    phishing_n   = int((combined["label"] == 1).sum())
    legitimate_n = int((combined["label"] == 0).sum())

    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "url_training_data.csv")
    combined.to_csv(path, index=False)

    _set(
        status="done",
        finished_at=datetime.now(timezone.utc).isoformat(),
        phishing_count=phishing_n,
        legitimate_count=legitimate_n,
        total=len(combined),
        sources_used=sources,
        error=(" | ".join(errors) if errors else None),
        data_path=path,
    )
    print(f"[ingest] Saved {len(combined):,} URLs -> {path}")
    return path
