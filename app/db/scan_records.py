import json
import uuid
from datetime import datetime

from app.db._helpers import abs_db_path, db_conn

DB_PATH = abs_db_path("phishguard.db")


def _init():
    with db_conn(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_records (
                id            TEXT PRIMARY KEY,
                timestamp     TEXT,
                input_type    TEXT,
                input_preview TEXT,
                prediction    TEXT,
                confidence    REAL,
                model_breakdown TEXT,
                reasoning     TEXT
            )
        """)
        # Indexes for the two most common access patterns
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_timestamp "
            "ON scan_records (timestamp DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_prediction "
            "ON scan_records (prediction, input_type)"
        )


def save_scan(scan_id: str, input_type: str, input_text: str,
              prediction: str, confidence: float,
              model_breakdown=None, reasoning=None):
    preview = (input_text or "")[:150]
    with db_conn(DB_PATH) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scan_records
               (id, timestamp, input_type, input_preview, prediction,
                confidence, model_breakdown, reasoning)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, datetime.utcnow().isoformat(), input_type, preview,
             prediction, confidence,
             json.dumps(model_breakdown) if model_breakdown else None,
             json.dumps(reasoning) if reasoning else None),
        )


def get_scans(limit: int = 50):
    with db_conn(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_records ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_analytics():
    """Aggregate via SQL - O(1) memory regardless of table size."""
    with db_conn(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT   prediction,
                     input_type,
                     COUNT(*)        AS cnt,
                     AVG(confidence) AS avg_conf
            FROM     scan_records
            GROUP BY prediction, input_type
            """
        ).fetchall()
        total_row = conn.execute(
            "SELECT COUNT(*), AVG(confidence) FROM scan_records"
        ).fetchone()

    total = total_row[0] or 0
    avg_confidence = round(total_row[1] or 0.0, 4)

    by_prediction: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for prediction, itype, cnt, _ in rows:
        pred = prediction or "unknown"
        it = itype or "unknown"
        by_prediction[pred] = by_prediction.get(pred, 0) + cnt
        by_type[it] = by_type.get(it, 0) + cnt

    return {
        "total": total,
        "by_prediction": by_prediction,
        "by_type": by_type,
        "avg_confidence": avg_confidence,
    }


import sqlite3   # kept for Row factory use above
_init()
