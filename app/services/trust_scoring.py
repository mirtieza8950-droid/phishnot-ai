"""
Feedback poisoning protection via submitter trust scoring.

Each submitter IP gets a trust score (0.0-1.0). The score degrades when
poisoning indicators are detected:
  - High submission rate (>10 in 24 hours)
  - Contradictions: same text, different label from prior submission
  - All-disagreement pattern: >90% of feedback contradicts the model (with >5 samples)

Feedback from submitters below TRUST_THRESHOLD is flagged and excluded from retraining.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from app.db.feedback import get_feedback_conn, get_feedback_conn_exclusive

TRUST_THRESHOLD = 0.40
RATE_WINDOW_HOURS = 24
RATE_LIMIT_COUNT = 10

# Aliases so the rest of this file is unchanged
_conn = get_feedback_conn
_conn_exclusive = get_feedback_conn_exclusive


def _text_fingerprint(text: str) -> str:
    """Stable 12-char hash of text for contradiction detection."""
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def compute_trust_score(submitter_ip: str) -> float:
    """
    Recompute trust score for an IP from its full feedback history.
    Returns a float in [0.0, 1.0].
    """
    with _conn() as conn:
        rows = conn.execute(
            "SELECT user_label, model_prediction, timestamp, text_fingerprint "
            "FROM feedback WHERE submitter_ip = ? ORDER BY timestamp DESC",
            (submitter_ip,),
        ).fetchall()

    if not rows:
        return 1.0

    total = len(rows)
    score = 1.0

    # ── Rate penalty: >RATE_LIMIT_COUNT submissions in 24h ──────────
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=RATE_WINDOW_HOURS)).isoformat()
    recent = sum(1 for r in rows if r[2] and r[2] >= cutoff)
    if recent > RATE_LIMIT_COUNT:
        excess = recent - RATE_LIMIT_COUNT
        score -= min(0.40, 0.04 * excess)

    # ── Contradiction penalty: same text fingerprint, different label ─
    seen: dict[str, str] = {}
    contradictions = 0
    for user_label, model_pred, ts, fp in rows:
        if fp and fp in seen and seen[fp] != user_label:
            contradictions += 1
        elif fp:
            seen[fp] = user_label
    if contradictions:
        contradiction_ratio = contradictions / total
        score -= contradiction_ratio * 0.50

    # ── All-disagreement penalty ─────────────────────────────────────
    if total >= 5:
        corrections = sum(1 for r in rows if r[0] != r[1])
        if corrections / total > 0.90:
            score -= 0.30

    return round(max(0.0, min(1.0, score)), 4)


def score_submission(
    submitter_ip: str,
    input_text: str,
    user_label: str,
    model_prediction: str,
) -> tuple[float, bool, str]:
    """
    Evaluate a new feedback submission.

    Returns:
        trust_score (float): current score for this submitter after this submission
        is_flagged (bool):   True if submission should be excluded from retraining
        reason (str):        human-readable flag reason or "ok"
    """
    fp = _text_fingerprint(input_text)
    flag_reason = "ok"

    # BEGIN IMMEDIATE serialises concurrent submissions from the same IP so the
    # rate-limit count and the subsequent INSERT are one atomic unit.
    with _conn_exclusive() as conn:
        prior = conn.execute(
            "SELECT user_label FROM feedback WHERE submitter_ip = ? AND text_fingerprint = ? LIMIT 1",
            (submitter_ip, fp),
        ).fetchone()

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=RATE_WINDOW_HOURS)).isoformat()
        recent_count = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE submitter_ip = ? AND timestamp >= ?",
            (submitter_ip, cutoff),
        ).fetchone()[0]

    if prior and prior[0] != user_label:
        flag_reason = f"contradiction: previously labeled '{prior[0]}' for identical text"

    if recent_count >= RATE_LIMIT_COUNT:
        flag_reason = f"rate_limit: {recent_count} submissions in {RATE_WINDOW_HOURS}h"

    trust_score = compute_trust_score(submitter_ip)
    is_flagged = trust_score < TRUST_THRESHOLD or flag_reason != "ok"

    return trust_score, is_flagged, flag_reason


def get_trust_stats() -> list[dict]:
    """Return trust summary for all submitters - for the admin panel."""
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT submitter_ip,
                   COUNT(*) as total,
                   SUM(flagged) as flagged_count,
                   AVG(trust_score) as avg_trust,
                   MAX(timestamp) as last_seen
            FROM feedback
            WHERE submitter_ip IS NOT NULL
            GROUP BY submitter_ip
            ORDER BY avg_trust ASC, total DESC
            """,
        ).fetchall()

    return [
        {
            "ip": r[0],
            "total_submissions": r[1],
            "flagged_count": r[2] or 0,
            "avg_trust_score": round(r[3] or 1.0, 4),
            "last_seen": r[4],
            "status": "blocked" if (r[3] or 1.0) < TRUST_THRESHOLD else "trusted",
        }
        for r in rows
    ]
