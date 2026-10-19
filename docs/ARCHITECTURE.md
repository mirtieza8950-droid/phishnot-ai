# Architecture

How PhishNot AI is put together: inference pipeline, self-learning loop, data model, security layers, and deployment constraints.

---

## 1. System overview

```
                    ┌──────────────────────────────────────────────┐
                    │        Frontend (React 18 + Vite)            │
                    │   pages/ → components/ → api/phishguard.js   │
                    └───────────────────┬──────────────────────────┘
                                        │ fetch (session cookie)
                    ┌───────────────────▼──────────────────────────┐
                    │              FastAPI (app/main.py)           │
                    │  CORS · SessionMiddleware · SecureHeaders    │
                    │  SlowAPI rate limiter · SPA static handler   │
                    └───┬───────────────┬────────────────┬─────────┘
                        │               │                │
              ┌─────────▼────┐  ┌───────▼────────┐  ┌────▼───────────┐
              │  Scanning    │  │  Admin / ops   │  │  Specialist    │
              │  routers     │  │  routers       │  │  services      │
              │  scan, batch │  │  admin, audit  │  │  sandbox,      │
              └───────┬──────┘  └───────┬────────┘  │  brand, vishing│
                      │                 │           └────────────────┘
            ┌─────────▼──────────┐  ┌───▼───────────────────────┐
            │  Ensemble Engine   │  │  Self-learning pipeline   │
            │  + risk engine     │  │  consensus · canary ·     │
            │  + LIME / calibration│ │  quarantine · retraining  │
            └─────────┬──────────┘  └───────────┬───────────────┘
                      │                         │
        ┌─────────────▼─────────────┐   ┌───────▼──────────────┐
        │  model weights (models/)  │   │  SQLite (WAL mode)   │
        │  .pth · .pkl · tokenizers │   │  phishguard.db       │
        └───────────────────────────┘   │  feedback.db         │
                                        │  audit.log (hash chain)│
                                        └──────────────────────┘
```

**Key property:** the app is a monolith by design. FastAPI serves both the API and the built SPA, one process runs the scheduler, and SQLite backs all state — which makes deployment trivial (one container) but rules out serverless.

---

## 2. Inference pipeline

### 2.1 Ensemble composition

Four base models score each email, blended with weights read from `models/ensemble_config.pkl`:

| Component | Type | Weight | Features |
|---|---|---|---|
| Logistic Regression | linear, calibrated | 0.15 | tf-idf n-grams |
| Random Forest | tree ensemble | 0.15 | tf-idf n-grams |
| DeBERTa-v3-small | transformer + dense head | 0.40 | token semantics |
| DistilRoBERTa | transformer + dense head | 0.30 | token semantics |

All four emit a 3-class probability vector (`ham`, `phishing`, `spam`). Base probabilities are blended:

```
p_blend = 0.15·p_lr + 0.15·p_rf + 0.40·p_deberta + 0.30·p_distilroberta
```

### 2.2 Stacked meta-learner

The four *individual* probability vectors (12 features) are concatenated and fed to an **XGBoost meta-learner** (`models/meta_learner.pkl`) trained on stacked out-of-fold predictions plus feedback-derived corrections. The meta-learner is the final arbiter — it learns context-dependent model reliability (e.g. "trust the transformer more on urgent-tone phishing, trust LR more on bulk spam").

Code: `app/services/ensemble_engine.py:predict_email_ensemble`.

### 2.3 LoRA adapters (optional)

If `models/deberta_lora/` and `models/distilroberta_lora/` exist, PEFT adapters are loaded **on top of** the base transformer at startup. Inference routes through `PeftModel`, which returns a base-model output; the classifier head is then applied to `[CLS]` (the engine handles three possible output shapes — logits, `last_hidden_state`, or raw tensor).

### 2.4 Fallback behaviour

- **GPU OOM:** every `model.to(DEVICE)` is wrapped — on CUDA OOM the engine empties the cache, switches `DEVICE` to CPU, and continues. The app degrades to slower inference instead of failing startup.
- **Missing weights:** a missing `.pth` logs a warning and the component runs with random init. The startup path treats `deberta_dense.pth` as required for production accuracy but does not block boot.
- **Vision model:** Qwen2-VL loads **lazily on first screenshot call**, never at startup, to keep the GPU free for the ensemble.

### 2.5 URL path

URLs take a separate branch: lexical features (`app/utils/url_features.py` → `url_phishing_model.pkl`, gradient boosting) plus a dedicated **URL transformer** (DistilRoBERTa architecture fine-tuned on URL text; 96.3% accuracy / 0.9939 AUC). Results also flow through a domain whitelist (`models/domain_whitelist.json`) and Tranco top-list reputation check.

---

## 3. Self-learning system

The differentiator: user feedback becomes training signal, but only after surviving anti-poisoning defences.

### 3.1 Pipeline phases (`app/services/self_training_pipeline.py`)

| Phase | What happens |
|---|---|
| **1. Canary injection** | ~5% of feedback slots are seeded with samples of known correct labels. Users who systematically contradict canaries are flagged for penalty. |
| **2. Consensus tracking** | Feedback on identical text is grouped; `consensus_count` increments per agreeing submitter. Single-source corrections need multi-submit confirmation. |
| **3. Quarantine** | `should_quarantine()` holds a submission when: it mismatches the model at high confidence, comes from a low-trust submitter, or conflicts with consensus. Held rows sit in `feedback.quarantined=1` for admin review. |
| **4. Anomaly detection** | `detect_feedback_anomalies()` scans for burst patterns, trust outliers, and fingerprint collisions. |
| **5. Training export** | `export_training_data()` emits `texts[]` / `labels[]` from confirmed corrections only — quarantined and canary rows never reach training. |

### 3.2 Scheduling (`app/services/self_learning_scheduler.py`)

A daemon thread started from FastAPI startup, ticking every hour (no APScheduler dependency):

| Cadence | Task | Est. cost |
|---|---|---|
| Weekly | Meta-learner retrain (`model_retrainer.retrain_meta`) | ~2 min |
| Monthly | LoRA fine-tune (`train_lora_adapters.py` subprocess) | ~30 min |
| Quarterly | Alert prompting a full manual retrain | — |

On startup the "last run" timestamps are initialised to *now* so a fresh deployment never fires a training job immediately.

### 3.3 Safety gates

- **Accuracy guard:** `retrain_meta` evaluates the candidate against a held-out split; if accuracy regresses below the incumbent, the swap aborts and the old model stays live.
- **Atomic writes:** new weights are written to a temp file and `os.replace()`d into place — a crash mid-write never corrupts a live model.
- **Version pinning:** `models/meta_version.txt` records the active meta-learner version, surfaced through `/admin/self-learning/status`.

### 3.4 Admin surface

`GET /admin/feedback/stats` (pipeline counters), `GET /admin/feedback/quarantine` (review queue), `POST /admin/feedback/{id}/approve|reject`, `POST /admin/self-learning/run-now`, `POST /admin/lora/finetune`. The frontend mirrors these in `FeedbackTab.jsx` and `RetrainTab.jsx`.

---

## 4. Data model

Two SQLite databases in WAL mode (`app/db/_helpers.py` — `journal_mode=WAL`, `synchronous=NORMAL`, `BEGIN IMMEDIATE` for writers, `check_same_thread=False` for FastAPI's threadpool).

### `feedback.db` — `feedback` table

| Column | Purpose |
|---|---|
| `id`, `scan_id` | identity |
| `user_label`, `model_prediction` | disagreement pair |
| `input_text`, `input_type` | payload (email/URL) |
| `submitter_ip`, `trust_score` | attribution + trust |
| `flagged`, `flag_reason` | anomaly verdict |
| `text_fingerprint` | de-duplication / collision detection |
| `consensus_count` | agreeing submitters on same text |
| `canary` | seeded sample flag |
| `quarantined`, `quarantine_reason` | hold state for admin review |
| `validated_by` | admin who approved/rejected |

Schema evolution uses `ALTER TABLE ADD COLUMN` guarded by a **whitelisted column list** (`_ALLOWED_MIGRATIONS`) — column names are never interpolated from user input, and indexes are created *after* migration.

### `phishguard.db` — scan records + users

Scan history (`/history`, `/analytics`) and user accounts with `admin` / `end_user` roles.

### `audit.log` — tamper-evident event chain

Append-only JSONL where each entry embeds a hash of the previous entry. `GET /audit/verify` recomputes the chain and reports integrity — anyone with file access can detect tampering.

---

## 5. Security model

| Layer | Implementation |
|---|---|
| **AuthN** | Session cookies (Starlette `SessionMiddleware`) + optional Google/Microsoft OAuth; password login for admin via rate-limited `POST /admin/verify` |
| **AuthZ** | `get_current_user` / `require_admin` dependencies; sensitive routes (sandbox, lookalikes, eval, retrain, admin) are admin-only |
| **Rate limiting** | SlowAPI, e.g. analyst chat 20/min, AI thinking 10/min |
| **Secure headers** | `X-Content-Type-Options`, `X-Frame-Options: DENY`, HSTS, `Referrer-Policy`, `Permissions-Policy` |
| **SSRF guard** | `app/utils/ssrf_guard.py` blocks private/loopback/link-local targets before any fetch |
| **Prompt-injection firewall** | `app/services/prompt_firewall.py` — `detect_injection()` runs on analyst chat and AI-thinking inputs before they reach an LLM |
| **Input validation** | Pydantic models, magic-byte + size checks on uploads, hostname regex on whitelist entries |
| **Secrets** | `.env` (gitignored), committed `.env.example` only; startup warns if default secrets are still in use |
| **Rate-limited prompt surface** | LLM endpoints require prior auth and are capped |

---

## 6. Frontend

React 18 SPA under `frontend/src`:

- `pages/` — one route per capability (ScanEmail, ScanUrl, BatchLedger, BrandProtection, BrowserSandbox, OAuthDetector, MobilePhishing, VishingAnalyzer, PhishingKit, AdminPanel, ScanHistory, Analytics, …)
- `components/admin/` — ten admin tabs (Feedback, Retrain, Health, Trust, Audit, RedTeam, Adversarial, Whitelist, Users, Data)
- `api/phishguard.js` — single API client module (all fetch wrappers live here)
- `context/AuthContext.jsx` — session state

Dev: Vite on `:3000` proxying `/api` → `:8000`. Prod: `npm run build` → `frontend/dist`, mounted by FastAPI as a SPA catch-all.

---

## 7. Deployment

### Supported path: Docker

`Dockerfile` → `python:3.12-slim` + tesseract/libzbar + Node 20, builds the frontend inside the image, runs `uvicorn app.main:app --host 0.0.0.0 --port 8000`. `docker-compose.yml` mounts `models/`, `phishguard.db`, `feedback.db` for persistence and requires `SESSION_SECRET` / `ADMIN_PASSWORD` from the environment.

### Constraints worth knowing

1. **Long-running process required** — the self-learning scheduler, WHOIS threads, and Tranco refresher are in-process threads. FaaS platforms will not work.
2. **Persistent filesystem required** — SQLite databases, the hash-chained audit log, whitelist JSON, and model retraining all write to disk.
3. **~2 GB RAM minimum** — all transformer weights load at startup; a 1 vCPU / 1 GB free-tier instance is not enough.
4. **HuggingFace cache** — set `HF_CACHE_DIR` in `.env` to keep base-model downloads between restarts (defaults to `~/.cache/phishnot`).
5. **Model weights are not in git** (1.4 GB) — clone → train → serve. Datasets are likewise excluded; see `training.py` and the download scripts.

### Configuration reference

All settings live in `app/core/config.py` (pydantic-settings, reads `.env`):

| Key | Default | Notes |
|---|---|---|
| `SESSION_SECRET` | placeholder | **required in production** |
| `ADMIN_PASSWORD` | placeholder | **required in production** |
| `ADMIN_EMAIL` | `""` | if set, only this OAuth email receives admin |
| `ALLOWED_ORIGINS` | localhost:3000 | comma-separated |
| `HF_CACHE_DIR` | `~/.cache/phishnot` | HF download cache |
| `VISION_MODEL_ID` | `Qwen/Qwen2-VL-2B-Instruct` | lazy-loaded |
| `DEVICE` | auto (cuda if available) | falls back to CPU on OOM |
| `GROQ_API_KEY` / `OPENROUTER_API_KEY` / `GOOGLE_API_KEY` | unset | analyst chat |
| `VT_API_KEY` / `OTX_API_KEY` / `PHISHTANK_APP_KEY` | unset | threat intel |

---

## 8. Testing strategy

| Suite | Covers | Count |
|---|---|---|
| `test_capabilities.py` | every API capability end-to-end via `TestClient` | 71 |
| `test_stress.py` | pipeline internals: canary rate, quarantine rules, consensus, scheduler lifecycle, endpoint presence, syntax | 64 |
| `test_deep_pass2.py` | E2E feedback flows, concurrent DB access, canary penalty, API contract | 44 |

Suites run against the real FastAPI app with `TestClient`, so they exercise routing, auth dependencies, and response shapes — not just unit logic.
