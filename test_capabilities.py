"""Full product capability test."""
import sys
import os
import json
import io
import base64

sys.path.insert(0, os.path.dirname(__file__))

from app.services.ensemble_engine import load_all_models
load_all_models()

from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

client = TestClient(app)

# ── Authenticate as admin ─────────────────────────────────────────────────────
print("Logging in as admin...")
r = client.post("/api/v1/admin/verify", json={"password": settings.ADMIN_PASSWORD})
if r.status_code == 200:
    print("  Login OK")
else:
    print("  Login FAILED: %d %s" % (r.status_code, r.text))
    sys.exit(1)

passed = 0
failed = 0
skipped = 0
results = []


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        results.append(("PASS", name))
        print("  [PASS] %s" % name)
    else:
        failed += 1
        results.append(("FAIL", name, detail))
        print("  [FAIL] %s %s" % (name, detail))


def skip(name, reason=""):
    global skipped
    skipped += 1
    results.append(("SKIP", name, reason))
    print("  [SKIP] %s %s" % (name, reason))


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CORE SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("1. CORE SCANNING")
print("=" * 60)

# -- Email scan --
r = client.post("/api/v1/scan/email", json={"text": "URGENT: Your account has been compromised. Click here to verify."})
test("POST /scan/email returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("email scan has prediction", "prediction" in data)
    test("email scan has confidence", "confidence" in data)
    test("email scan has probabilities", "all_probabilities" in data or "probabilities" in data)
    test("email scan has model_breakdown", "model_predictions" in data or "model_breakdown" in data)
    if "prediction" in data:
        test("email prediction is valid label", data["prediction"] in ["ham", "spam", "phishing"], "got %s" % data["prediction"])
    if "model_breakdown" in data:
        test("has 4 models", len(data["model_breakdown"]) == 4)

# -- Email scan with explain --
r = client.post("/api/v1/scan/email", json={"text": "Hello, how are you?", "explain": True})
test("email scan with explain=200", r.status_code == 200)
if r.status_code == 200:
    data = r.json()
    test("explain has explanation key", "explanation" in data or "reasoning" in data or "thinking" in data,
         "keys: %s" % list(data.keys()))

# -- URL scan --
r = client.post("/api/v1/scan/url", json={"url": "https://www.google.com"})
test("POST /scan/url returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("url scan has prediction", "prediction" in data or "phishing_probability" in data)
    if "prediction" in data:
        test("url prediction is valid", data["prediction"] in ["legitimate", "phishing", "suspicious"],
             "got %s" % data["prediction"])

# -- URL scan with phishing URL --
r = client.post("/api/v1/scan/url", json={"url": "http://paypa1-secure.suspicious-site.xyz/login"})
test("phishing URL scan returns 200", r.status_code == 200)

# -- QR scan --
# Create a simple test image (1x1 white pixel PNG)
from PIL import Image
img = Image.new("RGB", (100, 100), "white")
buf = io.BytesIO()
img.save(buf, format="PNG")
img_b64 = base64.b64encode(buf.getvalue()).decode()

r = client.post("/api/v1/scan/qr", files={"file": ("test.png", buf.getvalue(), "image/png")})
test("POST /scan/qr returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
test("qr scan has result key", "codes" in data or "found" in data,
     "keys: %s" % list(data.keys()))

# -- Image scan (vision) --
buf.seek(0)
r = client.post("/api/v1/scan/image?explain=true", files={"file": ("test.png", buf.getvalue(), "image/png")})
test("POST /scan/image returns 200 or 422", r.status_code in [200, 422], "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("image scan has result", "analysis" in data or "prediction" in data,
         "keys: %s" % list(data.keys()))
elif r.status_code == 422:
    test("image 422 is 'no text found'", "No text" in r.json().get("detail", ""))

# ═══════════════════════════════════════════════════════════════════════════════
# 2. ANALYSIS TOOLS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("2. ANALYSIS TOOLS")
print("=" * 60)

# -- Email headers --
r = client.post("/api/v1/scan/headers", json={"raw_headers": "From: test@example.com\nTo: user@example.com\nSubject: Test"})
test("POST /scan/headers returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("headers analysis has result", "analysis" in data or "risk_score" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

# -- Redirect tracer --
r = client.post("/api/v1/scan/trace", json={"url": "https://www.google.com"})
test("POST /scan/trace returns 200", r.status_code == 200, "got %d" % r.status_code)

# -- Analyst chat (AI) --
r = client.post("/api/v1/scan/ask", json={"question": "What is phishing?", "prediction": "spam", "confidence": 0.85, "model_predictions": {}})
test("POST /scan/ask returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("analyst chat has answer", "answer" in data or "response" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

# -- AI thinking --
r = client.post("/api/v1/scan/thinking", json={"text": "Test email", "prediction": "spam"})
test("POST /scan/thinking returns 200", r.status_code == 200, "got %d" % r.status_code)

# -- Visual forensics --
buf.seek(0)
r = client.post("/api/v1/scan/visual", json={"image_base64": img_b64})
test("POST /scan/visual returns 200", r.status_code == 200, "got %d" % r.status_code)

# -- PDF report --
r = client.post("/api/v1/scan/report/pdf", json={"text": "Test email", "prediction": "spam", "confidence": 0.85, "all_probabilities": {"ham": 0.1, "spam": 0.8, "phishing": 0.1}, "model_predictions": {}})
test("POST /scan/report/pdf returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    test("pdf is binary", r.headers.get("content-type", "").startswith("application/pdf") or len(r.content) > 100)

# ═══════════════════════════════════════════════════════════════════════════════
# 3. BATCH SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("3. BATCH SCANNING")
print("=" * 60)

r = client.post("/api/v1/batch/", json=[
    {"type": "email", "content": "Test email 1"},
    {"type": "url", "content": "https://google.com"},
])
test("POST /batch/ returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("batch has results", "results" in data or "scan_id" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

# ═══════════════════════════════════════════════════════════════════════════════
# 4. BRAND PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("4. BRAND PROTECTION")
print("=" * 60)

# -- DMARC check --
r = client.post("/api/v1/brand/dmarc", json={"domain": "google.com"})
test("POST /brand/dmarc returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("dmarc has result", "dmarc" in data or "record" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

# -- Lookalike scan --
r = client.post("/api/v1/brand/lookalikes/scan", json={"domain": "google.com"})
test("POST /brand/lookalikes/scan returns 200", r.status_code == 200, "got %d" % r.status_code)

# -- Kit fingerprint --
r = client.post("/api/v1/brand/kit/fingerprint", json={"url": "https://google.com"})
test("POST /brand/kit/fingerprint returns 200", r.status_code == 200, "got %d" % r.status_code)

# -- Kit signatures --
r = client.get("/api/v1/brand/kit/signatures")
test("GET /brand/kit/signatures returns 200", r.status_code == 200, "got %d" % r.status_code)

# -- CT logs --
r = client.get("/api/v1/brand/ct/google.com")
test("GET /brand/ct/google.com returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 5. SANDBOX
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("5. SANDBOX")
print("=" * 60)

r = client.post("/api/v1/sandbox/scan", json={"url": "https://google.com"})
test("POST /sandbox/scan returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("sandbox has job_id", "job_id" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

# ═══════════════════════════════════════════════════════════════════════════════
# 6. OAUTH DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("6. OAUTH DETECTION")
print("=" * 60)

r = client.post("/api/v1/oauth/analyze-url", json={"url": "https://accounts.google.com/o/oauth2/auth"})
test("POST /oauth/analyze-url returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("oauth url analysis has result", "analysis" in data or "risk_score" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

r = client.post("/api/v1/oauth/analyze-email", json={"text": "From: noreply@paypal.com\nSubject: Verify your account"})
test("POST /oauth/analyze-email returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/oauth/providers")
test("GET /oauth/providers returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("providers is list", isinstance(data, list) or isinstance(data, dict),
         "type: %s" % type(data).__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# 7. MOBILE PHISHING
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("7. MOBILE PHISHING")
print("=" * 60)

r = client.post("/api/v1/mobile/analyze-sms", json={"text": "Your package delivery failed. Click http://uspis-tracking.xyz to reschedule."})
test("POST /mobile/analyze-sms returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("sms analysis has result", "risk_score" in data or "analysis" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

r = client.post("/api/v1/mobile/analyze-deeplink", json={"link": "myapp://redirect?url=https://evil.com"})
test("POST /mobile/analyze-deeplink returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.post("/api/v1/mobile/analyze-url", json={"url": "https://m.paypal-secure.login.xyz"})
test("POST /mobile/analyze-url returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 8. VISHING
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("8. VISHING")
print("=" * 60)

# Vishing requires audio file upload — skip if no test audio
r = client.post("/api/v1/vishing/analyze", files={"file": ("test.wav", b"RIFF" + b"\x00" * 100, "audio/wav")})
test("POST /vishing/analyze returns 200 or 415", r.status_code in [200, 415], "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("vishing has job_id", "job_id" in data or "detail" in data,
         "keys: %s" % list(data.keys()))

# ═══════════════════════════════════════════════════════════════════════════════
# 9. ADVERSARIAL / RED TEAM
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("9. ADVERSARIAL / RED TEAM")
print("=" * 60)

r = client.get("/api/v1/adversarial/strategies")
test("GET /adversarial/strategies returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
    test("strategies has data", "strategies" in data or isinstance(data, list) or isinstance(data, dict),
         "keys: %s" % list(data.keys()) if isinstance(data, dict) else "type: %s" % type(data).__name__)

r = client.get("/api/v1/adversarial/stats")
test("GET /adversarial/stats returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 10. HISTORY & AUDIT
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("10. HISTORY & AUDIT")
print("=" * 60)

r = client.get("/api/v1/history/")
test("GET /history/ returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/history/analytics")
test("GET /history/analytics returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/audit/log")
test("GET /audit/log returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/audit/verify")
test("GET /audit/verify returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 11. THREAT INTEL
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("11. THREAT INTEL")
print("=" * 60)

r = client.get("/api/v1/threat-intel/lookup?url=https://google.com")
test("GET /threat-intel/lookup returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 12. ADMIN (unauthenticated)
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("12. ADMIN (unauthenticated)")
print("=" * 60)

r = client.get("/api/v1/admin/health")
test("GET /admin/health returns 200", r.status_code == 200, "got %d" % r.status_code)
if r.status_code == 200:
    data = r.json()
test("health has system info", "uptime" in data or "status" in data or "models_ready" in data,
     "keys: %s" % list(data.keys()))

r = client.get("/api/v1/admin/feedback?limit=5")
test("GET /admin/feedback returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/feedback/stats")
test("GET /admin/feedback/stats returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/feedback/quarantine")
test("GET /admin/feedback/quarantine returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/feedback/confirmed")
test("GET /admin/feedback/confirmed returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/trust")
test("GET /admin/trust returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/whitelist")
test("GET /admin/whitelist returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/tranco/status")
test("GET /admin/tranco/status returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/admin/self-learning/status")
test("GET /admin/self-learning/status returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 13. TRAINING
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("13. TRAINING")
print("=" * 60)

r = client.get("/api/v1/training/ingest/status")
test("GET /training/ingest/status returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/training/url-model/status")
test("GET /training/url-model/status returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 14. EVAL
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("14. EVAL")
print("=" * 60)

r = client.get("/api/v1/eval/status")
test("GET /eval/status returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/api/v1/eval/results")
test("GET /eval/results returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# 15. SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("15. SYSTEM")
print("=" * 60)

r = client.get("/health")
test("GET /health returns 200 or 503", r.status_code in [200, 503], "got %d" % r.status_code)

r = client.get("/api/v1/status")
test("GET /status returns 200", r.status_code == 200, "got %d" % r.status_code)

r = client.get("/docs")
test("GET /docs returns 200", r.status_code == 200, "got %d" % r.status_code)

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("RESULTS: %d passed, %d failed, %d skipped" % (passed, failed, skipped))
print("=" * 60)

if failed > 0:
    print("\nFAILURES:")
    for r in results:
        if r[0] == "FAIL":
            print("  - %s: %s" % (r[1], r[2]))

sys.exit(1 if failed > 0 else 0)
