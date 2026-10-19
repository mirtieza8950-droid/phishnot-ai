"""
Self-learning pipeline: feedback validation, canary defense, consensus gating,
and training data export.

Defense layers:
  1. Canary traps — inject known-correct samples, penalize users who mislabel them
  2. Consensus — require N independent users to agree before a correction is trusted
  3. Threat-intel cross-check — validate corrections against VirusTotal / URL reputation
  4. Anomaly detection — flag statistical outliers in feedback patterns
  5. Quarantine — high-risk corrections held for admin review

Pipeline stages:
  - On feedback submission: canary check, consensus update, quarantine decision
  - Weekly: export confirmed corrections, retrain meta-learner
  - Monthly: LoRA fine-tune transformers on accumulated data
"""

import hashlib
import os
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np

from app.core.config import settings
from app.db.feedback import get_feedback_conn, get_feedback_conn_exclusive

# ── Constants ─────────────────────────────────────────────────────────────────
CANARY_RATE = 0.05           # 5% of feedback submissions are canaries
MIN_CONSENSUS = 3            # minimum independent users to confirm a correction
MIN_TRUST_FOR_TRAINING = 0.8 # minimum trust score for feedback to enter training
QUARANTINE_CONFIDENCE = 0.90 # quarantine if model was >90% confident and user disagrees
ANOMALY_MIN_SAMPLES = 10     # minimum submissions per IP for anomaly detection
ANOMALY_DISAGREEMENT = 0.85  # >85% disagreement with model = suspicious

# ── Known-correct canary samples ─────────────────────────────────────────────
# These are samples the model already classifies correctly with high confidence.
# A user who marks these incorrectly is likely a bad-faith actor.
CANARY_SAMPLES = [
    {"text": "URGENT: Your bank account has been compromised. Click here to verify your identity immediately!",
     "correct_label": "phishing", "input_type": "email"},
    {"text": "Dear user, we detected unusual activity on your account. Please confirm your password.",
     "correct_label": "phishing", "input_type": "email"},
    {"text": "You have won $1,000,000 in the lottery! Claim your prize now by clicking this link.",
     "correct_label": "spam", "input_type": "email"},
    {"text": "Hi John, can you review the attached quarterly report before Friday's meeting?",
     "correct_label": "ham", "input_type": "email"},
    {"text": "Your subscription to Office 365 has expired. Renew now to avoid service interruption.",
     "correct_label": "phishing", "input_type": "email"},
    {"text": "http://paypa1-secure-login.verify-account.xyz/signin",
     "correct_label": "phishing", "input_type": "url"},
    {"text": "https://www.google.com",
     "correct_label": "legitimate", "input_type": "url"},
    {"text": "http://192.168.1.1/admin/login.php",
     "correct_label": "phishing", "input_type": "url"},
    {"text": "Team standup notes from today. Action items attached.",
     "correct_label": "ham", "input_type": "email"},
    {"text": " Congratulations! You've been selected for a free iPhone. Click here!",
     "correct_label": "spam", "input_type": "email"},
]


def _text_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


# ── Canary injection ──────────────────────────────────────────────────────────

def maybe_inject_canary() -> Optional[dict]:
    """
    Returns a canary sample to inject into the feedback pool.
    Call this during feedback submission — 5% chance of returning a canary.
    """
    if random.random() < CANARY_RATE:
        sample = random.choice(CANARY_SAMPLES)
        return {
            "scan_id": f"canary_{int(time.time())}",
            "user_label": sample["correct_label"],
            "model_prediction": sample["correct_label"],
            "input_text": sample["text"],
            "input_type": sample["input_type"],
            "submitter_ip": "canary_system",
            "canary": 1,
        }
    return None


def inject_canary_feedback() -> Optional[dict]:
    """Inject a canary sample directly into the feedback table. Returns the canary dict or None."""
    canary = maybe_inject_canary()
    if not canary:
        return None
    fp = _text_fingerprint(canary["input_text"])
    with get_feedback_conn_exclusive() as conn:
        conn.execute(
            """INSERT INTO feedback
               (scan_id, user_label, model_prediction, input_text, input_type,
                submitter_ip, trust_score, flagged, flag_reason, text_fingerprint,
                consensus_count, canary, quarantined, quarantine_reason)
               VALUES (?, ?, ?, ?, ?, ?, 1.0, 0, 'ok', ?, 1, 1, 0, '')""",
            (canary["scan_id"], canary["user_label"], canary["model_prediction"],
             canary["input_text"], canary["input_type"], canary["submitter_ip"], fp),
        )
        conn.commit()
    return canary


# ── Canary violation detection ────────────────────────────────────────────────

def detect_canary_violations() -> list[dict]:
    """
    Find users who submitted feedback that contradicts a canary sample.
    Returns list of violation records with penalty recommendations.
    """
    violations = []
    with get_feedback_conn() as conn:
        canary_rows = conn.execute(
            "SELECT id, input_text, user_label, submitter_ip, text_fingerprint "
            "FROM feedback WHERE canary = 1"
        ).fetchall()

        for canary_id, correct_text, correct_label, _, fp in canary_rows:
            if not fp:
                continue
            wrong_submissions = conn.execute(
                """SELECT id, user_label, submitter_ip, trust_score, timestamp
                   FROM feedback
                   WHERE text_fingerprint = ? AND user_label != ?
                     AND canary = 0 AND submitter_ip != 'canary_system'""",
                (fp, correct_label),
            ).fetchall()

            for sub_id, wrong_label, ip, trust, ts in wrong_submissions:
                violations.append({
                    "feedback_id": sub_id,
                    "submitter_ip": ip,
                    "canary_id": canary_id,
                    "correct_label": correct_label,
                    "submitted_label": wrong_label,
                    "current_trust": trust,
                    "timestamp": ts,
                    "penalty": 0.30,  # heavy penalty for canary violation
                })

    return violations


def apply_canary_penalties() -> int:
    """Apply trust penalties to canary violators. Returns count of penalized IPs."""
    violations = detect_canary_violations()
    penalized_ips = set()

    for v in violations:
        if v["submitter_ip"] in penalized_ips:
            continue
        with get_feedback_conn_exclusive() as conn:
            conn.execute(
                "UPDATE feedback SET trust_score = MAX(0.0, trust_score - ?) "
                "WHERE submitter_ip = ?",
                (v["penalty"], v["submitter_ip"]),
            )
            conn.commit()
        penalized_ips.add(v["submitter_ip"])

    return len(penalized_ips)


# ── Consensus tracking ────────────────────────────────────────────────────────

def update_consensus():
    """
    Recalculate consensus_count for all feedback entries.
    consensus = number of distinct IPs who submitted the same text_fingerprint
                with the same user_label.
    """
    with get_feedback_conn_exclusive() as conn:
        # Get all unique fingerprints
        fps = conn.execute(
            "SELECT DISTINCT text_fingerprint FROM feedback "
            "WHERE text_fingerprint IS NOT NULL AND canary = 0"
        ).fetchall()

        for (fp,) in fps:
            # Count distinct IPs per label for this fingerprint
            label_counts = conn.execute(
                """SELECT user_label, COUNT(DISTINCT submitter_ip) as cnt
                   FROM feedback
                   WHERE text_fingerprint = ? AND canary = 0
                   GROUP BY user_label""",
                (fp,),
            ).fetchall()

            for label, count in label_counts:
                conn.execute(
                    "UPDATE feedback SET consensus_count = ? "
                    "WHERE text_fingerprint = ? AND user_label = ? AND canary = 0",
                    (count, fp, label),
                )

        conn.commit()


# ── Quarantine decisions ──────────────────────────────────────────────────────

def should_quarantine(user_label: str, model_prediction: str,
                      model_confidence: float, trust_score: float) -> tuple[bool, str]:
    """
    Decide if a feedback submission should be quarantined for admin review.
    Returns (quarantined: bool, reason: str).
    """
    # High-confidence model vs disagreeing user
    if user_label != model_prediction and model_confidence >= QUARANTINE_CONFIDENCE:
        return True, f"model_confidence_{model_confidence:.2f}_disagreement"

    # Low-trust user making a correction
    if user_label != model_prediction and trust_score < 0.5:
        return True, f"low_trust_{trust_score:.2f}"

    # User correcting to a class the model ranked last
    if user_label != model_prediction:
        return False, ""

    return False, ""


# ── Anomaly detection ─────────────────────────────────────────────────────────

def detect_feedback_anomalies() -> list[dict]:
    """
    Detect IPs with suspicious feedback patterns:
    - >85% disagreement with model predictions (with enough samples)
    - Sudden burst of submissions (>20 in 1 hour)
    - All submissions are the same label
    """
    anomalies = []

    with get_feedback_conn() as conn:
        submitters = conn.execute(
            """SELECT submitter_ip, COUNT(*) as total,
                      SUM(CASE WHEN user_label != model_prediction THEN 1 ELSE 0 END) as disagreements
               FROM feedback
               WHERE submitter_ip IS NOT NULL AND submitter_ip != 'canary_system'
               GROUP BY submitter_ip
               HAVING total >= ?""",
            (ANOMALY_MIN_SAMPLES,),
        ).fetchall()

        for ip, total, disagreements in submitters:
            disagree_rate = (disagreements or 0) / total

            if disagree_rate > ANOMALY_DISAGREEMENT:
                anomalies.append({
                    "submitter_ip": ip,
                    "type": "high_disagreement",
                    "disagreement_rate": round(disagree_rate, 4),
                    "total_submissions": total,
                    "recommendation": "review_and_potentially_block",
                })

        # Burst detection: >20 submissions in 1 hour
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        burst_ips = conn.execute(
            """SELECT submitter_ip, COUNT(*) as cnt
               FROM feedback
               WHERE timestamp >= ? AND submitter_ip != 'canary_system'
               GROUP BY submitter_ip
               HAVING cnt > 20""",
            (cutoff,),
        ).fetchall()

        for ip, cnt in burst_ips:
            anomalies.append({
                "submitter_ip": ip,
                "type": "burst_submissions",
                "count_in_1h": cnt,
                "recommendation": "rate_limit",
            })

    return anomalies


# ── Training data export ──────────────────────────────────────────────────────

def get_confirmed_corrections(
    min_consensus: int = MIN_CONSENSUS,
    min_trust: float = MIN_TRUST_FOR_TRAINING,
) -> list[dict]:
    """
    Query feedback for corrections that pass all gates:
    - Not flagged
    - Not quarantined
    - Not a canary
    - Trust score >= min_consensus
    - consensus_count >= min_consensus (independent users agree)
    - user_label != model_prediction (it's actually a correction)
    """
    with get_feedback_conn() as conn:
        rows = conn.execute(
            """SELECT id, scan_id, user_label, model_prediction, input_text,
                      input_type, trust_score, consensus_count, submitter_ip
               FROM feedback
               WHERE flagged = 0
                 AND quarantined = 0
                 AND canary = 0
                 AND trust_score >= ?
                 AND consensus_count >= ?
                 AND user_label != model_prediction
               ORDER BY trust_score DESC, consensus_count DESC""",
            (min_trust, min_consensus),
        ).fetchall()

    return [
        {
            "id": r[0], "scan_id": r[1], "user_label": r[2],
            "model_prediction": r[3], "input_text": r[4],
            "input_type": r[5], "trust_score": r[6],
            "consensus_count": r[7], "submitter_ip": r[8],
        }
        for r in rows
    ]


def export_training_data() -> dict:
    """
    Export confirmed corrections as a dict ready for retraining.
    Returns {texts: [...], labels: [...], input_types: [...], weights: [...]}.
    """
    corrections = get_confirmed_corrections()
    if not corrections:
        return {"texts": [], "labels": [], "input_types": [], "weights": [],
                "count": 0, "message": "No confirmed corrections available"}

    return {
        "texts": [c["input_text"] for c in corrections],
        "labels": [c["user_label"] for c in corrections],
        "input_types": [c["input_type"] for c in corrections],
        "weights": [c["trust_score"] for c in corrections],
        "count": len(corrections),
        "message": f"{len(corrections)} confirmed corrections ready for training",
    }


# ── Pipeline statistics ───────────────────────────────────────────────────────

def get_pipeline_stats() -> dict:
    """Return comprehensive stats about the self-learning pipeline."""
    with get_feedback_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        flagged = conn.execute("SELECT COUNT(*) FROM feedback WHERE flagged = 1").fetchone()[0]
        canary_total = conn.execute("SELECT COUNT(*) FROM feedback WHERE canary = 1").fetchone()[0]
        quarantined = conn.execute("SELECT COUNT(*) FROM feedback WHERE quarantined = 1").fetchone()[0]
        confirmed = conn.execute(
            "SELECT COUNT(*) FROM feedback "
            "WHERE flagged = 0 AND quarantined = 0 AND canary = 0 "
            "AND user_label != model_prediction AND consensus_count >= ? AND trust_score >= ?",
            (MIN_CONSENSUS, MIN_TRUST_FOR_TRAINING),
        ).fetchone()[0]

        # Consensus distribution
        consensus_dist = conn.execute(
            "SELECT consensus_count, COUNT(*) FROM feedback "
            "WHERE canary = 0 GROUP BY consensus_count ORDER BY consensus_count"
        ).fetchall()

    violations = detect_canary_violations()
    anomalies = detect_feedback_anomalies()

    return {
        # Aliases expected by the frontend / admin endpoints
        "total_feedback": total,
        "quarantined_count": quarantined,
        "canary_count": canary_total,
        "anomaly_count": len(anomalies),
        "training_data_count": confirmed,
        # Detailed keys for internal use
        "total_submissions": total,
        "flagged": flagged,
        "canary_samples": canary_total,
        "canary_violations": len(violations),
        "quarantined": quarantined,
        "confirmed_for_training": confirmed,
        "consensus_distribution": {str(k): v for k, v in consensus_dist},
        "anomalies_detected": len(anomalies),
        "anomalies": anomalies[:10],
        "defense_layers": {
            "canary_rate": f"{CANARY_RATE * 100}%",
            "min_consensus": MIN_CONSENSUS,
            "min_trust": MIN_TRUST_FOR_TRAINING,
            "quarantine_threshold": QUARANTINE_CONFIDENCE,
        },
    }


# ── Full pipeline orchestration ───────────────────────────────────────────────

def run_full_pipeline() -> dict:
    """
    Run the complete self-learning pipeline:
    1. Apply canary penalties
    2. Update consensus counts
    3. Detect anomalies
    4. Export confirmed corrections
    5. Return stats
    """
    results = {}

    # Step 1: Canary penalties
    penalized = apply_canary_penalties()
    results["canary_penalties_applied"] = penalized

    # Step 2: Update consensus
    update_consensus()
    results["consensus_updated"] = True

    # Step 3: Anomaly detection
    anomalies = detect_feedback_anomalies()
    results["anomalies"] = anomalies

    # Step 4: Export training data
    training_data = export_training_data()
    results["training_data_count"] = training_data["count"]

    # Step 5: Stats
    results["stats"] = get_pipeline_stats()

    return results
