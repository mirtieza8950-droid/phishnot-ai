"""Stress test for the self-learning system."""
import sys
import os
import sqlite3
import time

sys.path.insert(0, os.path.dirname(__file__))

from app.services.self_training_pipeline import (
    should_quarantine, inject_canary_feedback, update_consensus,
    detect_feedback_anomalies, get_pipeline_stats, get_confirmed_corrections,
    export_training_data, detect_canary_violations, apply_canary_penalties,
)
from app.services.self_learning_scheduler import get_scheduler, start_scheduler, stop_scheduler
from app.db.feedback import get_feedback_conn, get_feedback_conn_exclusive

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


# ── 1. Import check ───────────────────────────────────────────────────────────
print("\n=== 1. Import check ===")
try:
    from app.services.self_training_pipeline import should_quarantine
    from app.services.self_learning_scheduler import get_scheduler
    from app.services.model_retrainer import retrain_meta
    from app.services.ensemble_engine import DeBertaDenseClassifier, DistilRobertaDenseClassifier
    from app.api.v1.admin import router
    check("all imports resolve", True)
except Exception as e:
    check("all imports resolve", False, str(e))

# ── 2. DB migration ───────────────────────────────────────────────────────────
print("\n=== 2. DB migration ===")
conn = sqlite3.connect("feedback.db")
cols = [row[1] for row in conn.execute("PRAGMA table_info(feedback)")]
expected_cols = ["consensus_count", "canary", "quarantined", "quarantine_reason", "validated_by"]
for c in expected_cols:
    check("column %s exists" % c, c in cols)
rows_before = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
conn.close()
# Migration must be idempotent and non-destructive: re-running init must not drop rows
from app.db.feedback import init_feedback_db
init_feedback_db()
conn = sqlite3.connect("feedback.db")
rows_after = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
conn.close()
check("existing data preserved (rows unchanged: %d)" % rows_before,
      rows_after == rows_before, "before %d -> after %d" % (rows_before, rows_after))

# ── 3. should_quarantine ──────────────────────────────────────────────────────
print("\n=== 3. should_quarantine ===")
q, r = should_quarantine("ham", "spam", 0.95, 1.0)
check("high-conf mismatch quarantined", q == True)
q, r = should_quarantine("ham", "spam", 0.45, 1.0)
check("low-conf mismatch NOT quarantined", q == False)
q, r = should_quarantine("spam", "spam", 0.99, 1.0)
check("agreement NOT quarantined", q == False)
q, r = should_quarantine("ham", "spam", 0.5, 0.1)
check("low trust quarantined", q == True)
q, r = should_quarantine("ham", "spam", 0.5, 0.0)
check("trust=0 quarantined", q == True)
q, r = should_quarantine("", "", 0.99, 1.0)
check("empty strings handled", isinstance(q, bool))
try:
    q, r = should_quarantine("ham", "spam", 0.0, 1.0)
    check("zero confidence handled", isinstance(q, bool))
except Exception as e:
    check("zero confidence handled", False, str(e))

# ── 4. Canary injection ──────────────────────────────────────────────────────
print("\n=== 4. Canary injection ===")
with sqlite3.connect("feedback.db") as c:
    c.execute("UPDATE feedback SET canary = 0")
    c.commit()
injected = sum(1 for _ in range(100) if inject_canary_feedback())
check("canary injected >0 in 100 attempts", injected > 0, "got %d" % injected)
check("canary rate ~5%%", 1 <= injected <= 20, "got %d" % injected)
canary_count = sqlite3.connect("feedback.db").execute(
    "SELECT COUNT(*) FROM feedback WHERE canary = 1"
).fetchone()[0]
check("canary samples in DB", canary_count > 0)

# ── 5. Consensus update ──────────────────────────────────────────────────────
print("\n=== 5. Consensus update ===")
try:
    update_consensus()
    check("update_consensus no crash", True)
except Exception as e:
    check("update_consensus no crash", False, str(e))

# ── 6. Anomaly detection ─────────────────────────────────────────────────────
print("\n=== 6. Anomaly detection ===")
try:
    anomalies = detect_feedback_anomalies()
    check("detect_feedback_anomalies returns list", isinstance(anomalies, list))
except Exception as e:
    check("detect_feedback_anomalies", False, str(e))

# ── 7. Pipeline stats ────────────────────────────────────────────────────────
print("\n=== 7. Pipeline stats ===")
stats = get_pipeline_stats()
for k in ["total_feedback", "quarantined_count", "canary_count",
           "anomaly_count", "training_data_count"]:
    check("stats has key '%s'" % k, k in stats)

# ── 8. Confirmed corrections ─────────────────────────────────────────────────
print("\n=== 8. Confirmed corrections ===")
corrections = get_confirmed_corrections()
check("get_confirmed_corrections returns list", isinstance(corrections, list))
for c in corrections:
    check("correction has input_text", "input_text" in c)
    check("correction has user_label", "user_label" in c)
    check("correction has trust_score", "trust_score" in c)

# ── 9. Export training data ───────────────────────────────────────────────────
print("\n=== 9. Export training data ===")
data = export_training_data()
check("export has texts key", "texts" in data)
check("export has labels key", "labels" in data)
check("export has count key", "count" in data)
check("texts/labels same length", len(data["texts"]) == len(data["labels"]))

# ── 10. Canary violations ─────────────────────────────────────────────────────
print("\n=== 10. Canary violations ===")
violations = detect_canary_violations()
check("returns list", isinstance(violations, list))

# ── 11. Canary penalties ──────────────────────────────────────────────────────
print("\n=== 11. Canary penalties ===")
penalties = apply_canary_penalties()
check("returns int", isinstance(penalties, int))

# ── 12. Scheduler ─────────────────────────────────────────────────────────────
print("\n=== 12. Scheduler ===")
import app.services.self_learning_scheduler as mod
mod._scheduler = None
s = get_scheduler()
st = s.status()
check("scheduler status has running", "running" in st)
check("scheduler not running initially", st["running"] == False)
start_scheduler()
time.sleep(0.3)
check("scheduler running after start", s.status()["running"] == True)
stop_scheduler()
time.sleep(0.5)
check("scheduler stopped after stop", s.status()["running"] == False)
st = s.status()
for k in ["next_meta_retrain", "next_lora_finetune", "next_full_retrain"]:
    check("status has '%s'" % k, k in st)

# ── 13. Admin endpoints ───────────────────────────────────────────────────────
print("\n=== 13. Admin endpoints ===")
from app.api.v1.admin import router
route_paths = set()
for route in router.routes:
    if hasattr(route, "path") and hasattr(route, "methods"):
        for m in route.methods:
            route_paths.add("%s %s" % (m, route.path))
expected_endpoints = [
    "GET /feedback/quarantine",
    "POST /feedback/{feedback_id}/approve",
    "POST /feedback/{feedback_id}/reject",
    "GET /feedback/stats",
    "GET /feedback/confirmed",
    "POST /self-learning/run",
    "GET /self-learning/status",
    "POST /self-learning/run-now",
    "POST /lora/finetune",
]
for ep in expected_endpoints:
    check("endpoint %s" % ep, ep in route_paths)

# ── 14. Edge cases: DB operations ─────────────────────────────────────────────
print("\n=== 14. Edge cases: DB operations ===")
# Insert feedback with minimal valid data
try:
    with get_feedback_conn_exclusive() as conn:
        conn.execute(
            """INSERT INTO feedback
               (scan_id, user_label, model_prediction, input_text,
                input_type, submitter_ip, trust_score)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("edge_test_1", "ham", "spam", "minimal text", "email", "192.168.1.1", 0.7),
        )
        conn.commit()
    check("insert minimal feedback", True)
except Exception as e:
    check("insert minimal feedback", False, str(e))

# Read it back
try:
    with get_feedback_conn() as conn:
        row = conn.execute(
            "SELECT user_label, model_prediction FROM feedback WHERE scan_id = ?",
            ("edge_test_1",)
        ).fetchone()
        check("read back feedback", row is not None and row[0] == "ham")
except Exception as e:
    check("read back feedback", False, str(e))

# Cleanup
with get_feedback_conn_exclusive() as conn:
    conn.execute("DELETE FROM feedback WHERE scan_id = ?", ("edge_test_1",))
    conn.commit()

# Approve non-existent feedback
try:
    with get_feedback_conn_exclusive() as conn:
        conn.execute(
            "UPDATE feedback SET quarantined = 0 WHERE id = ?", (999999,)
        )
        conn.commit()
    check("approve non-existent (no crash)", True)
except Exception as e:
    check("approve non-existent (no crash)", False, str(e))

# ── 15. Pipeline run_full_pipeline ────────────────────────────────────────────
print("\n=== 15. run_full_pipeline ===")
try:
    from app.services.self_training_pipeline import run_full_pipeline
    result = run_full_pipeline()
    check("run_full_pipeline returns dict", isinstance(result, dict))
    check("result has canary_penalties_applied", "canary_penalties_applied" in result)
    check("result has consensus_updated", "consensus_updated" in result)
    check("result has training_data_count", "training_data_count" in result)
    check("result has stats", "stats" in result)
except Exception as e:
    check("run_full_pipeline", False, str(e))

# ── 16. Syntax check all files ────────────────────────────────────────────────
print("\n=== 16. Syntax check ===")
import py_compile
files = [
    "app/services/self_training_pipeline.py",
    "app/services/self_learning_scheduler.py",
    "app/services/model_retrainer.py",
    "app/services/ensemble_engine.py",
    "app/api/v1/admin.py",
    "app/main.py",
    "app/db/feedback.py",
    "train_meta_learner.py",
    "train_lora_adapters.py",
]
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        check("syntax %s" % f, True)
    except py_compile.PyCompileError as e:
        check("syntax %s" % f, False, str(e))

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STRESS TEST RESULTS: %d passed, %d failed out of %d" % (passed, failed, passed + failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
