"""
Shared SQLite connection utilities for all database modules.

Every connection opened through db_conn():
  - Uses WAL journal mode (concurrent reads don't block writes; multiple
    FastAPI workers can read simultaneously without "database is locked" errors)
  - Uses NORMAL synchronous mode (safe with WAL, ~3x faster than FULL)
  - Has check_same_thread=False (required for async/threaded FastAPI)
  - Commits on clean exit, rolls back on exception, always closes

abs_db_path() anchors bare filenames to the project root so the database
location is deterministic regardless of the process working directory.
"""

import pathlib
import sqlite3
from contextlib import contextmanager

# app/db/_helpers.py -> app/db -> app -> project root
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def abs_db_path(name: str) -> str:
    """Return an absolute path for *name*, anchored at the project root."""
    p = pathlib.Path(name)
    return str(p) if p.is_absolute() else str(_PROJECT_ROOT / name)


@contextmanager
def db_conn(path: str):
    """
    Open a WAL-mode SQLite connection.

    Usage::

        with db_conn(DB_PATH) as conn:
            conn.execute("INSERT ...")
        # auto-committed; connection closed
    """
    conn = sqlite3.connect(abs_db_path(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def db_conn_exclusive(path: str):
    """
    Like db_conn() but opens with BEGIN IMMEDIATE, serialising concurrent
    writers at the DB level. Use this for check-then-insert patterns where
    a TOCTOU race would otherwise be possible.
    """
    conn = sqlite3.connect(
        abs_db_path(path),
        check_same_thread=False,
        isolation_level="IMMEDIATE",
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
