# API Reference

**Base URL:** `http://localhost:8000/api/v1` · **Interactive docs:** [`/docs`](http://localhost:8000/docs) (Swagger) · `/redoc`

---

## Authentication

All endpoints use **session-cookie auth**. Obtain a session one of two ways:

**Admin password login**

```http
POST /api/v1/admin/verify
Content-Type: application/json

{ "password": "<ADMIN_PASSWORD from .env>" }
```

`200` sets a session cookie (store it for subsequent requests); `401` on a bad password (rate-limited).

**OAuth login** (requires client credentials in `.env`)

```http
GET /api/v1/auth/login/{google|microsoft}     → redirects to provider
GET /api/v1/auth/{provider}/callback           → sets session on return
GET /api/v1/auth/me                            → current user
POST /api/v1/auth/logout                       → revoke session
```

**Access levels**

| Level | Requirement |
|---|---|
| 🌐 Public | none (e.g. `/auth/login/*`, `/brand/kit/signatures`) |
| 👤 User | any valid session |
| 🛡️ Admin | session with `role=admin` |

Errors follow FastAPI conventions: `401` unauthenticated, `403` insufficient role, `422` validation failure (with field-level `detail`), `413` payload too large.

---

## Scanning

### `POST /scan/email` 👤

Classify an email body across the full ensemble.

```json
{ "text": "URGENT: your account will be suspended...", "explain": true }
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `text` | string | — | email body |
| `explain` | bool | `true` | include LIME attribution |

**Response**

```json
{
  "prediction": "phishing",
  "confidence": 0.94,
  "confidence_interval": [0.91, 0.97],
  "all_probabilities": { "ham": 0.02, "phishing": 0.94, "spam": 0.04 },
  "model_predictions": {
    "logistic_regression": { "prediction": "phishing", "confidence": 0.87 },
    "random_forest":       { "prediction": "phishing", "confidence": 0.83 },
    "deberta_dense":       { "prediction": "phishing", "confidence": 0.96 },
    "distilroberta":       { "prediction": "phishing", "confidence": 0.92 }
  },
  "explanation": [ { "word": "urgent", "weight": 0.31 }, "…" ],
  "reasoning":   { "risk_score": 87, "risk_level": "high", "risk_story": "…" },
  "risk_info":   { "score": 87, "level": "high" },
  "scan_id": "uuid",
  "warning": null
}
```

### `POST /scan/url` 👤

```json
{ "url": "https://example-login.verify-secure.top/auth" }
```

Response mirrors the email shape plus `url` and `whitelisted` (true if the domain is on the whitelist — scan short-circuits).

### `POST /scan/image` 👤 (multipart)

| Part | Value |
|---|---|
| `file` | image (PNG/JPEG, size + magic-byte validated) |
| `explain` | query param, default `true` |

Returns OCR-extracted text, QR detections, and the classification of the extracted content. `422` if no text is extractable.

### `POST /scan/qr` 👤 (multipart)

| Part | Value |
|---|---|
| `file` | image containing QR code(s) |

```json
{ "found": true, "codes": ["https://…"], "warning": null }
```

### `POST /scan/headers` 👤

```json
{ "raw_headers": "From: …\nTo: …\nSubject: …\nReceived: …" }
```

Header-forensics result: SPF/DKIM/DMARC status, routing anomalies, spoof indicators.

### `POST /scan/trace` 👤

```json
{ "url": "https://bit.ly/abc", "max_hops": 12 }
```

`max_hops` is 1–20 (default 12). Walks the redirect chain with SSRF-guarded fetches; returns each hop and the final destination.

### `POST /scan/ask` 👤 · 20/min

Grounded analyst Q&A. Pass the scan context you want the LLM to reason over:

```json
{
  "prediction": "phishing",
  "confidence": 0.94,
  "model_predictions": { "…": { "prediction": "…", "confidence": 0.9 } },
  "explanation": [],
  "reasoning": { "risk_score": 87, "risk_level": "high" },
  "text": "original scanned text",
  "question": "Which part of this email is the actual payload?"
}
```

```json
{ "question": "…", "answer": "…" }
```

Prompt-injection attempts are rejected: `{"answer": "I cannot process that request due to security concerns."}`.

### `POST /scan/thinking` 👤 · 10/min

```json
{ "text": "…", "prediction": "phishing" }
```

→ `{ "thinking": "…" }` — a short chain-of-thought style narrative.

### `POST /scan/visual` 👤

```json
{ "image_base64": "…", "url_hint": "https://suspect.example" }
```

Screenshot/page visual analysis via the vision model (lazy-loaded).

### `POST /scan/report/pdf` 👤 · `GET /scan/report/{scan_id}` 👤

```json
{
  "prediction": "phishing",
  "confidence": 0.94,
  "all_probabilities": { "ham": 0.02, "phishing": 0.94, "spam": 0.04 },
  "model_predictions": { "…": { "prediction": "…", "confidence": 0.9 } },
  "reasoning": {},
  "scan_id": "uuid"
}
```

Returns a binary PDF (forensic report with verdict, model consensus, attack analysis).

---

## Batch

### `POST /batch/` 👤

Body is a **JSON array** (max 500 items; `413` beyond that). Each item carries `text` *or* `url`:

```json
[
  { "text": "…" },
  { "url": "https://…" },
  { "other": "…" }
]
```

```json
{
  "total": 3,
  "results": [
    { "index": 0, "type": "email", "prediction": "phishing", "confidence": 0.94,
      "risk_score": 87, "risk_level": "high", "scan_id": "" },
    { "index": 1, "type": "url", "prediction": "suspicious", "confidence": 0.71, "…": "…" },
    { "index": 2, "error": "item must have 'text' or 'url'" }
  ]
}
```

---

## Brand protection

| Method & path | Auth | Body / params | Purpose |
|---|---|---|---|
| `POST /brand/dmarc` | 👤 | `{ "domain": "example.com" }` | DMARC/DKIM/SPF posture |
| `POST /brand/lookalikes/scan` | 🛡️ | `{ "domain": "example.com" }` | generate + DNS-probe lookalikes (40 workers) |
| `GET /brand/lookalikes/status/{domain}` | 👤 | — | async scan progress |
| `GET /brand/lookalikes/preview/{domain}` | 👤 | — | candidate lookalike list |
| `POST /brand/kit/fingerprint` | 👤 | `{ "url": "…" }` | fingerprint phishing kit |
| `GET /brand/kit/signatures` | 🌐 | — | known kit signature metadata |
| `GET /brand/ct/{domain}` | 👤 | — | Certificate Transparency log entries |

---

## Browser sandbox

| Method & path | Auth | Notes |
|---|---|---|
| `POST /sandbox/scan` | 🛡️ | `{ "url": "…", … }` → `{ "job_id": "…" }` (async) |
| `GET /sandbox/status/{job_id}` | 🛡️ | job progress |
| `GET /sandbox/result/{job_id}` | 🛡️ | DOM / JS / network / screenshot / summary tabs |

Uses Playwright headless Chromium; each job is a background task.

---

## OAuth phishing detection

| Method & path | Body | Result |
|---|---|---|
| `POST /oauth/analyze-url` | `{ "url": "…" }` | consent-flow / token-theft indicators |
| `POST /oauth/analyze-email` | `{ "email": "…" }` | phishing-OAuth lure detection |
| `GET /oauth/providers` 🌐 | — | supported provider list |

---

## Mobile phishing

| Method & path | Body |
|---|---|
| `POST /mobile/analyze-sms` | `{ "text": "SMS body" }` |
| `POST /mobile/analyze-deeplink` | `{ "url": "myapp://reset?token=…" }` |
| `POST /mobile/analyze-url` | `{ "url": "https://…" }` |

---

## Vishing analysis

| Method & path | Auth | Notes |
|---|---|---|
| `POST /vishing/analyze` | 🌐 | multipart audio upload → `{ "job_id": "…" }` |
| `GET /vishing/status/{job_id}` | 🌐 | transcription progress (Whisper) |
| `GET /vishing/result/{job_id}` | 🌐 | transcript + social-engineering analysis |

`415` if the uploaded media type isn't supported.

---

## Adversarial / red team

| Method & path | Auth | Body |
|---|---|---|
| `GET /adversarial/strategies` 🌐 | — | available perturbation strategies |
| `POST /adversarial/generate` | 🛡️ | see below |
| `POST /adversarial/export` | 🛡️ | `{ "variants": [...], "true_label": "phishing" }` |
| `GET /adversarial/download` | 🛡️ | generated CSV |
| `GET /adversarial/stats` | 🛡️ | variant counts per strategy |

```json
{
  "text": "min 10 chars, max 5000",
  "true_label": "phishing | spam | ham",
  "strategies": ["…"],
  "n_per_strategy": 3,
  "seed": 42
}
```

### Evaluation harness

| Method & path | Auth | Notes |
|---|---|---|
| `POST /eval/run` | 🛡️ | `?max_samples=500` (10–5000), background task |
| `GET /eval/status` | 🛡️ | run progress |
| `GET /eval/results` | 🛡️ | per-model + ensemble metrics, confusion matrices → `eval_results.json` |

---

## History & audit

| Method & path | Auth | Result |
|---|---|---|
| `GET /history/` | 🛡️ | scan history |
| `GET /history/analytics` | 🛡️ | aggregate statistics |
| `GET /audit/log` | 🛡️ | audit events |
| `GET /audit/verify` | 🛡️ | hash-chain integrity check |

---

## Threat intelligence

### `GET /threat-intel/lookup` 👤

| Query | Required | Notes |
|---|---|---|
| `url` | ✅ | 4–2000 chars; scheme auto-prefixed |

Enriches with VirusTotal, AlienVault OTX, and PhishTank (keys from `.env`; unconfigured sources degrade gracefully):

```json
{
  "overall_threat_level": "high",
  "cached": false,
  "virustotal": { "malicious": 12 },
  "otx": { "pulse_count": 3 },
  "phishtank": { "status": "phish" }
}
```

---

## Training data

| Method & path | Auth | Body |
|---|---|---|
| `POST /training/ingest` | 🛡️ | `{ "use_phishing_db": true, "use_kaggle": true, "max_phishing_db": 20000, "max_kaggle": 100000 }` |
| `GET /training/ingest/status` | 🛡️ | ingestion progress |
| `POST /training/url-model/retrain` | 🛡️ | triggers URL model retrain |
| `GET /training/url-model/status` | 🛡️ | retrain progress / last metrics |

---

## Admin

Everything below requires 🛡️ admin except `POST /admin/verify`.

### Auth & system

| Method & path | Body | Purpose |
|---|---|---|
| `POST /admin/verify` 🌐 | `{ "password": "…" }` | create admin session |
| `GET /admin/health` | — | uptime, CPU/memory/disk, file sizes, DB rows, model state |
| `POST /admin/retrain` | — | manual meta-learner retrain |

### Feedback & self-learning

| Method & path | Purpose |
|---|---|
| `POST /admin/feedback` | submit feedback `{ "scan_id", "user_label", "model_prediction", "input_text", "input_type" }` |
| `GET /admin/feedback` | list feedback |
| `GET /admin/feedback/stats` | pipeline counters (total, quarantined, canary, anomalies, training rows) |
| `GET /admin/feedback/quarantine` | quarantine review queue |
| `POST /admin/feedback/{id}/approve` | release a quarantined row into training |
| `POST /admin/feedback/{id}/reject` | reject with `{ "reason": "…" }` |
| `GET /admin/feedback/confirmed` | validated corrections available for training |
| `POST /admin/self-learning/run` | run the full pipeline once |
| `GET /admin/self-learning/status` | scheduler state + next run times |
| `POST /admin/self-learning/run-now` | force a scheduled task |
| `POST /admin/lora/finetune` | launch LoRA fine-tune |

### Trust, whitelist, users, reputation

| Method & path | Purpose |
|---|---|
| `GET /admin/trust` | per-contributor trust scores |
| `GET /admin/whitelist` · `POST` · `DELETE` | domain whitelist (`{ "domain": "…" }`, validated by hostname regex) |
| `GET /admin/users` | accounts |
| `PATCH /admin/users/{id}/role` | `{ "role": "admin" | "end_user" }` |
| `PATCH /admin/users/{id}/status` | enable/disable |
| `GET /admin/tranco/status` · `POST /admin/tranco/refresh` | Tranco top-list cache |

---

## Response conventions

- **Timestamps** are UTC.
- **Confidence** is a float 0–1; `risk_score` is 0–100 with a `risk_level` of `low | medium | high | critical`.
- **`scan_id`** is a UUID returned by scan endpoints — reference it in feedback and report requests.
- **Async jobs** (`sandbox`, `vishing`) return `job_id`; poll `status` then fetch `result`.
- **Rate-limited endpoints** return `429` with `Retry-After`.
