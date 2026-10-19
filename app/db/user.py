"""User model and DB helpers."""
import uuid
from datetime import datetime, timezone

from app.db._helpers import abs_db_path, db_conn, db_conn_exclusive

DB_PATH = abs_db_path("phishguard.db")

VALID_ROLES = {"admin", "end_user"}

_ALLOWED_USER_MIGRATIONS: list[tuple[str, str]] = [
    ("disabled",   "INTEGER DEFAULT 0"),
    ("created_at", "TEXT"),
]


def _init_users():
    with db_conn(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         TEXT PRIMARY KEY,
                email      TEXT UNIQUE,
                name       TEXT,
                provider   TEXT,
                role       TEXT DEFAULT 'end_user',
                disabled   INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        for col, defn in _ALLOWED_USER_MIGRATIONS:
            if col not in existing_cols:
                try:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
                except Exception:
                    pass


_init_users()


def _row(conn, query, *args) -> dict | None:
    import sqlite3
    conn.row_factory = sqlite3.Row
    row = conn.execute(query, args).fetchone()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    with db_conn(DB_PATH) as conn:
        return _row(conn, "SELECT * FROM users WHERE email = ?", email)


def get_user_by_id(user_id: str) -> dict | None:
    with db_conn(DB_PATH) as conn:
        return _row(conn, "SELECT * FROM users WHERE id = ?", user_id)


def create_user(email: str, name: str, provider: str) -> dict:
    """
    Create a new user.  Role assignment (F-31):
      - If ADMIN_EMAIL is set in config, only that email address gets the admin role.
      - Otherwise the first registered user becomes admin (original behaviour).
    This prevents an attacker who registers before the legitimate admin from
    claiming the admin role permanently.
    """
    from app.core.config import settings

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with db_conn_exclusive(DB_PATH) as conn:
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        admin_email = getattr(settings, "ADMIN_EMAIL", "").strip().lower()

        if admin_email:
            # Explicit admin email set - only grant admin to that address
            role = "admin" if email.lower() == admin_email else "end_user"
        else:
            # Fallback: first registered user becomes admin
            role = "admin" if existing == 0 else "end_user"

        conn.execute(
            "INSERT OR IGNORE INTO users "
            "(id, email, name, provider, role, disabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)",
            (user_id, email, name, provider, role, now),
        )

    user = get_user_by_email(email)
    if user:
        return user
    return {
        "id": user_id, "email": email, "name": name,
        "provider": provider, "role": role, "disabled": 0, "created_at": now,
    }


def list_users() -> list[dict]:
    import sqlite3
    with db_conn(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def set_user_role(user_id: str, role: str) -> dict | None:
    if role not in VALID_ROLES:
        return None
    with db_conn(DB_PATH) as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    return get_user_by_id(user_id)


def set_user_disabled(user_id: str, disabled: bool) -> dict | None:
    with db_conn(DB_PATH) as conn:
        conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
    return get_user_by_id(user_id)
