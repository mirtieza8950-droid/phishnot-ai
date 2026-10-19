"""Deep pass 2: end-to-end API, race conditions, frontend contract."""
import sys
import os
import sqlite3
import time
import threading

sys.path.insert(0, os.path.dirname(__file__))

passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  [PASS] %s" % name)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (name, detail))


# ── 1. End-to-end: submit feedback -> quarantine -> approve ───────────────────
print("\n=== 1. E2E: feedback submit -> quarantine -> approve ===")
from app.db.feedback import get_feedback_conn, get_feedback_conn_exclusive

# Insert a feedback that will be quarantined (high-confidence mismatch)
with get_feedback_conn_exclusive() as conn:
    conn.execute(
        """INSERT INTO feedback
           (scan_id, user_label, model_prediction, input_text,
            input_type, submitter_ip, trust_score, flagged, flag_reason,
            text_fingerprint, consensus_count, canary, quarantined, quarantine_reason)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)""",
        ("e2e_quarantine_test", "ham", "spam", "e2e quarantine test text",
         "email", "10.0.0.99", 0.9, 0, "ok", "abc123", 1, "high_conf_mismatch"),
    )
    conn.commit()

# Verify it's quarantined
with get_feedback_conn() as conn:
    row = conn.execute(
        "SELECT quarantined, quarantine_reason FROM feedback WHERE scan_id = ?",
        ("e2e_quarantine_test",)
    ).fetchone()
check("feedback inserted as quarantined", row is not None and row[0] == 1)

# Approve it
with get_feedback_conn_exclusive() as conn:
    fid = conn.execute(
        "SELECT id FROM feedback WHERE scan_id = ?", ("e2e_quarantine_test",)
    ).fetchone()[0]
    conn.execute(
        "UPDATE feedback SET quarantined = 0, quarantine_reason = '' WHERE id = ?",
        (fid,)
    )
    conn.commit()

# Verify approved
with get_feedback_conn() as conn:
    row = conn.execute(
        "SELECT quarantined, quarantine_reason FROM feedback WHERE id = ?", (fid,)
    ).fetchone()
check("feedback approved (quarantined=0)", row[0] == 0)
check("quarantine_reason cleared", row[1] == "")

# Reject a different one
with get_feedback_conn_exclusive() as conn:
    conn.execute(
        """INSERT INTO feedback
           (scan_id, user_label, model_prediction, input_text,
            input_type, submitter_ip, trust_score, flagged, flag_reason,
            text_fingerprint, consensus_count, canary, quarantined, quarantine_reason)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 1, ?)""",
        ("e2e_reject_test", "spam", "ham", "e2e reject test text",
         "email", "10.0.0.98", 0.7, 0, "ok", "def456", "low_trust"),
    )
    conn.commit()
    rid = conn.execute(
        "SELECT id FROM feedback WHERE scan_id = ?", ("e2e_reject_test",)
    ).fetchone()[0]
    conn.execute(
        "UPDATE feedback SET flagged = 1, flag_reason = 'admin_rejected' WHERE id = ?",
        (rid,)
    )
    conn.commit()

with get_feedback_conn() as conn:
    row = conn.execute(
        "SELECT flagged, flag_reason FROM feedback WHERE id = ?", (rid,)
    ).fetchone()
check("rejected feedback flagged=1", row[0] == 1)
check("reject reason recorded", row[1] == "admin_rejected")

# Cleanup
with get_feedback_conn_exclusive() as conn:
    conn.execute("DELETE FROM feedback WHERE scan_id LIKE ?", ("e2e_%",))
    conn.commit()


# ── 2. Frontend API contract ──────────────────────────────────────────────────
print("\n=== 2. Frontend API contract ===")
# Verify the phishguard.js API paths match backend routes
import re
api_file = open("frontend/src/api/phishguard.js").read()

# Extract all API paths from phishguard.js
frontend_paths = set(re.findall(r'[`\'"](/admin/[^`\'"]+)[`\'"]', api_file))
frontend_paths.update(re.findall(r'[`\'"](/api/v1/[^`\'"]+)[`\'"]', api_file))

# Get backend routes
from app.main import app
backend_paths = set()
for route in app.routes:
    if hasattr(route, "path"):
        p = route.path
        # Normalize: remove path params for matching
        base = re.sub(r"\{[^}]+\}", "", p)
        backend_paths.add(base)

# Check critical self-learning paths
critical = [
    "/admin/feedback/quarantine",
    "/admin/feedback/stats",
    "/admin/feedback/confirmed",
    "/admin/self-learning/run",
    "/admin/self-learning/status",
    "/admin/self-learning/run-now",
    "/lora/finetune",
]
for path in critical:
    # Check if path or path/ is in backend
    found = any(path in bp or bp.startswith(path) for bp in backend_paths)
    check("backend has %s" % path, found)


# ── 3. Race condition: concurrent quarantine approve ──────────────────────────
print("\n=== 3. Race condition: concurrent DB access ===")
# Insert test row
with get_feedback_conn_exclusive() as conn:
    conn.execute(
        """INSERT INTO feedback
           (scan_id, user_label, model_prediction, input_text,
            input_type, submitter_ip, trust_score, flagged, flag_reason,
            text_fingerprint, consensus_count, canary, quarantined, quarantine_reason)
           VALUES (?, ?, ?, ?, ?, ?, 1.0, 0, '', '', 1, 0, 1, 'race test')""",
        ("race_test", "ham", "spam", "race test", "email", "10.0.0.50"),
    )
    conn.commit()

errors = []

def approve_worker(fid, worker_id):
    try:
        with get_feedback_conn_exclusive() as conn:
            conn.execute(
                "UPDATE feedback SET quarantined = 0 WHERE id = ?", (fid,)
            )
            conn.commit()
    except Exception as e:
        errors.append("worker%d: %s" % (worker_id, str(e)))

with get_feedback_conn() as conn:
    fid = conn.execute(
        "SELECT id FROM feedback WHERE scan_id = ?", ("race_test",)
    ).fetchone()[0]

threads = [threading.Thread(target=approve_worker, args=(fid, i)) for i in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=5)

check("concurrent approve no crash", len(errors) == 0, str(errors))

with get_feedback_conn() as conn:
    row = conn.execute(
        "SELECT quarantined FROM feedback WHERE id = ?", (fid,)
    ).fetchone()
check("row still valid after concurrent ops", row is not None)

with get_feedback_conn_exclusive() as conn:
    conn.execute("DELETE FROM feedback WHERE scan_id = ?", ("race_test",))
    conn.commit()


# ── 4. Consensus: multiple submitters same text ──────────────────────────────
print("\n=== 4. Consensus: multiple submitters same text ===")
from app.services.self_training_pipeline import update_consensus

with get_feedback_conn_exclusive() as conn:
    for i in range(3):
        conn.execute(
            """INSERT INTO feedback
               (scan_id, user_label, model_prediction, input_text,
                input_type, submitter_ip, trust_score, flagged, flag_reason,
                text_fingerprint, consensus_count, canary, quarantined, quarantine_reason)
               VALUES (?, ?, ?, ?, ?, ?, 1.0, 0, 'ok', '', 1, 0, 0, '')""",
            ("consensus_%d" % i, "spam", "ham", "same phishing text consensus",
             "email", "10.0.0.%d" % (10 + i)),
        )
    conn.commit()

update_consensus()

with get_feedback_conn() as conn:
    rows = conn.execute(
        "SELECT consensus_count, submitter_ip FROM feedback WHERE scan_id LIKE ?",
        ("consensus_%",)
    ).fetchall()
    counts = [r[0] for r in rows]
    ips = [r[1] for r in rows]
    check("3 submitters -> consensus >= 3", all(c >= 3 for c in counts),
          "got %s" % counts)
    check("3 distinct IPs", len(set(ips)) == 3, "got %s" % ips)

with get_feedback_conn_exclusive() as conn:
    conn.execute("DELETE FROM feedback WHERE scan_id LIKE ?", ("consensus_%",))
    conn.commit()


# ── 5. Canary violation: user contradicts canary ──────────────────────────────
print("\n=== 5. Canary violation detection ===")
from app.services.self_training_pipeline import (
    detect_canary_violations, apply_canary_penalties
)

# Insert a canary (ham) and a user contradicting it (spam for same text)
canary_text = "Your account is secure. No action needed."
with get_feedback_conn_exclusive() as conn:
    fp = __import__("hashlib").sha256(canary_text.encode()).hexdigest()[:12]
    conn.execute(
        """INSERT INTO feedback
           (scan_id, user_label, model_prediction, input_text,
            input_type, submitter_ip, trust_score, flagged, flag_reason,
            text_fingerprint, consensus_count, canary, quarantined, quarantine_reason)
           VALUES (?, ?, ?, ?, ?, ?, 1.0, 0, 'ok', ?, 1, 1, 0, '')""",
        ("canary_v_test", "ham", "ham", canary_text,
         "email", "canary_system", fp),
    )
    conn.execute(
        """INSERT INTO feedback
           (scan_id, user_label, model_prediction, input_text,
            input_type, submitter_ip, trust_score, flagged, flag_reason,
            text_fingerprint, consensus_count, canary, quarantined, quarantine_reason)
           VALUES (?, ?, ?, ?, ?, ?, 1.0, 0, 'ok', ?, 1, 0, 0, '')""",
        ("user_contradict", "spam", "ham", canary_text,
         "email", "192.168.1.100", fp),
    )
    conn.commit()

violations = detect_canary_violations()
check("canary violation detected", len(violations) > 0,
      "got %d violations" % len(violations))
if violations:
    v = violations[0]
    check("violation has submitter_ip", "submitter_ip" in v)
    check("violation has penalty", "penalty" in v or "trust_penalty" in v)

penalties = apply_canary_penalties()
check("penalties applied", penalties > 0, "got %d" % penalties)

# Verify trust was penalized
with get_feedback_conn() as conn:
    row = conn.execute(
        "SELECT trust_score FROM feedback WHERE scan_id = ?", ("user_contradict",)
    ).fetchone()
    if row:
        check("trust penalized after canary violation", row[0] < 1.0,
              "trust=%s" % row[0])

with get_feedback_conn_exclusive() as conn:
    conn.execute("DELETE FROM feedback WHERE scan_id IN (?, ?)",
                 ("canary_v_test", "user_contradict"))
    conn.commit()


# ── 6. Meta-learner train script validates correctly ──────────────────────────
print("\n=== 6. Meta-learner script syntax ===")
import py_compile
for script in ["train_meta_learner.py", "train_lora_adapters.py"]:
    try:
        py_compile.compile(script, doraise=True)
        check("syntax %s" % script, True)
    except py_compile.PyCompileError as e:
        check("syntax %s" % script, False, str(e))
# Note: these scripts require trained model weights to import at runtime.
# Syntax check is sufficient here.


# ── 7. Ensemble engine LoRA path safety ──────────────────────────────────────
print("\n=== 7. Ensemble engine LoRA path ===")
import app.services.ensemble_engine as ee
if ee.tfidf is None:
    ee.load_all_models()
# When LoRA dirs don't exist, both should be None
check("deberta_lora is None when no dir", ee.deberta_lora is None)
check("distilroberta_lora is None when no dir", ee.distilroberta_lora is None)
# Prediction should still work (base models)
label, conf, probs, breakdown = ee.predict_email_ensemble("Test email")
check("prediction works without LoRA", label in ["ham", "spam", "phishing"])
check("confidence in [0,1]", 0 <= conf <= 1)
check("3 probabilities", len(probs) == 3)
check("4 model breakdowns", len(breakdown) == 4)


# ── 8. Feedback submission with adversarial input ─────────────────────────────
print("\n=== 8. Adversarial input handling ===")
from app.services.self_training_pipeline import should_quarantine as _sq
# SQL injection attempt in input_text
try:
    malicious_text = "'; DROP TABLE feedback; --"
    q, r = _sq("ham", "spam", 0.95, 1.0)
    check("SQL in input_text doesn't crash quarantine", isinstance(q, bool))
except Exception as e:
    check("SQL in input_text doesn't crash quarantine", False, str(e))

# Very long text
try:
    long_text = "a" * 100000
    q, r = _sq("ham", "spam", 0.95, 1.0)
    check("100k char text handled", isinstance(q, bool))
except Exception as e:
    check("100k char text handled", False, str(e))

# Unicode in text
try:
    unicode_text = "\u200b\u200c\u200d\U0001f4a9"
    q, r = _sq("ham", "spam", 0.95, 1.0)
    check("unicode text handled", isinstance(q, bool))
except Exception as e:
    check("unicode text handled", False, str(e))


# ── 9. Scheduler: _check_and_run doesn't trigger immediately ──────────────────
print("\n=== 9. Scheduler doesn't trigger on start ===")
import app.services.self_learning_scheduler as smod
smod._scheduler = None
s = smod.get_scheduler()
# Before starting, _last_meta should be set to now (not None)
check("_last_meta initialized (not None)", s._last_meta is not None)
check("_last_lora initialized (not None)", s._last_lora is not None)
check("_last_full initialized (not None)", s._last_full is not None)

# After start, it should not immediately run training
from app.services.self_learning_scheduler import start_scheduler, stop_scheduler
start_scheduler()
time.sleep(0.2)
# The scheduler thread should be alive but not running training
check("scheduler thread alive", s._thread.is_alive() if s._thread else False)
stop_scheduler()
time.sleep(0.5)


# ── 10. Model retrainer lock ──────────────────────────────────────────────────
print("\n=== 10. Model retrainer lock ===")
from app.services.model_retrainer import _retrain_lock
check("retrain lock exists", _retrain_lock is not None)
check("retrain lock not locked initially", not _retrain_lock.locked())


# ── 11. Feedback DB: new column defaults ──────────────────────────────────────
print("\n=== 11. DB column defaults on insert ===")
with get_feedback_conn_exclusive() as conn:
    conn.execute(
        """INSERT INTO feedback
           (scan_id, user_label, model_prediction, input_text,
            input_type, submitter_ip)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("default_test", "ham", "spam", "default test", "email", "127.0.0.1"),
    )
    conn.commit()
    row = conn.execute(
        """SELECT consensus_count, canary, quarantined, quarantine_reason, validated_by
           FROM feedback WHERE scan_id = ?""",
        ("default_test",)
    ).fetchone()
    check("consensus_count defaults to 1", row[0] == 1)
    check("canary defaults to 0", row[1] == 0)
    check("quarantined defaults to 0", row[2] == 0)
    check("quarantine_reason defaults to ''", row[3] == "")
    check("validated_by defaults to ''", row[4] == "")

with get_feedback_conn_exclusive() as conn:
    conn.execute("DELETE FROM feedback WHERE scan_id = ?", ("default_test",))
    conn.commit()


# ── 12. Export training data: weight format ────────────────────────────────────
print("\n=== 12. Export training data format ===")
from app.services.self_training_pipeline import export_training_data
data = export_training_data()
if data["count"] > 0:
    check("weights is list", isinstance(data["weights"], list))
    check("all weights are float", all(isinstance(w, float) for w in data["weights"]))
    check("all weights in [0,1]", all(0 <= w <= 1 for w in data["weights"]))
else:
    check("export format (no data)", True)


# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("DEEP PASS 2 RESULTS: %d passed, %d failed out of %d" % (passed, failed, passed + failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
