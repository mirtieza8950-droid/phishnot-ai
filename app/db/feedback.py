from contextlib import contextmanager

from app.core.config import settings
from app.db._helpers import abs_db_path, db_conn, db_conn_exclusive

_FEEDBACK_DB = abs_db_path(settings.FEEDBACK_DB)

# F-19: explicit whitelist of allowed migration columns - never interpolate user data
_ALLOWED_MIGRATIONS: list[tuple[str, str]] = [
    ("input_type",         "TEXT DEFAULT 'email'"),
    ("submitter_ip",       "TEXT"),
    ("trust_score",        "REAL DEFAULT 1.0"),
    ("flagged",            "INTEGER DEFAULT 0"),
    ("flag_reason",        "TEXT DEFAULT 'ok'"),
    ("text_fingerprint",   "TEXT"),
    # Phase 1+4: self-learning defense layers
    ("consensus_count",    "INTEGER DEFAULT 1"),
    ("canary",             "INTEGER DEFAULT 0"),
    ("quarantined",        "INTEGER DEFAULT 0"),
    ("quarantine_reason",  "TEXT DEFAULT ''"),
    ("validated_by",       "TEXT DEFAULT ''"),
]


@contextmanager
def get_feedback_conn():
    with db_conn(_FEEDBACK_DB) as conn:
        yield conn


@contextmanager
def get_feedback_conn_exclusive():
    with db_conn_exclusive(_FEEDBACK_DB) as conn:
        yield conn


def init_feedback_db():
    with db_conn(_FEEDBACK_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id          TEXT,
                user_label       TEXT,
                model_prediction TEXT,
                input_text       TEXT,
                timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
                input_type       TEXT DEFAULT 'email',
                submitter_ip     TEXT,
                trust_score      REAL DEFAULT 1.0,
                flagged          INTEGER DEFAULT 0,
                flag_reason      TEXT DEFAULT 'ok',
                text_fingerprint TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_feedback_ip_ts "
            "ON feedback (submitter_ip, timestamp DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_feedback_fingerprint "
            "ON feedback (text_fingerprint)"
        )
        # Migrate older schema - only whitelisted column names are ever interpolated
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(feedback)")}
        for col, definition in _ALLOWED_MIGRATIONS:
            if col not in existing_cols:
                try:
                    # col and definition are from the hardcoded whitelist above, never user input
                    conn.execute(f"ALTER TABLE feedback ADD COLUMN {col} {definition}")
                except Exception:
                    pass
        # Create indexes AFTER migration so columns exist
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_feedback_consensus "
            "ON feedback (consensus_count DESC, trust_score DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_feedback_quarantine "
            "ON feedback (quarantined, timestamp DESC)"
        )


init_feedback_db()
