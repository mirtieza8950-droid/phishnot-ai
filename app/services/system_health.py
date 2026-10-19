"""
System health snapshot for the admin dashboard.
Uses psutil when available; falls back to platform-safe stubs.
"""
import os, time

_START_TIME = time.time()


def _file_size_kb(path: str) -> float:
    try:
        return round(os.path.getsize(path) / 1024, 1)
    except OSError:
        return 0.0


def _count_lines(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def get_health() -> dict:
    from app.core.config import settings
    import app.services.ensemble_engine as engine

    # ── Uptime ────────────────────────────────────────────────────────
    uptime_s = int(time.time() - _START_TIME)
    h, rem = divmod(uptime_s, 3600)
    m, s   = divmod(rem, 60)
    uptime_str = f"{h}h {m}m {s}s"

    # ── CPU / memory / disk (psutil optional) ─────────────────────────
    cpu_pct = mem_pct = mem_used_mb = mem_total_mb = disk_pct = disk_used_gb = disk_total_gb = None
    try:
        import psutil
        cpu_pct  = psutil.cpu_percent(interval=0.2)
        vm       = psutil.virtual_memory()
        mem_pct  = vm.percent
        mem_used_mb  = round(vm.used  / 1024 / 1024)
        mem_total_mb = round(vm.total / 1024 / 1024)
        du = psutil.disk_usage("/")
        disk_pct      = du.percent
        disk_used_gb  = round(du.used  / 1024**3, 2)
        disk_total_gb = round(du.total / 1024**3, 2)
    except Exception:
        pass  # psutil not installed or access denied

    # ── File sizes ────────────────────────────────────────────────────
    files = {
        "phishguard.db":          _file_size_kb("phishguard.db"),
        "feedback.db":            _file_size_kb(settings.FEEDBACK_DB),
        "audit.log":              _file_size_kb(settings.AUDIT_LOG_PATH),
        "eval_results.json":      _file_size_kb(settings.EVAL_RESULTS_PATH),
        "adversarial_generated.csv": _file_size_kb("adversarial_generated.csv"),
    }
    audit_entries = _count_lines(settings.AUDIT_LOG_PATH)

    # ── Model status ──────────────────────────────────────────────────
    models_loaded = engine.tfidf is not None and engine.lr_model is not None
    meta_active   = engine.use_meta_learner and engine.meta_model is not None

    meta_version = None
    version_file = os.path.join(settings.MODELS_DIR, "meta_version.txt")
    if os.path.exists(version_file):
        try:
            with open(version_file) as f:
                meta_version = int(f.read().strip())
        except Exception:
            pass

    # ── DB row counts ─────────────────────────────────────────────────
    from app.db._helpers import abs_db_path, db_conn
    scan_count = feedback_count = user_count = 0
    try:
        with db_conn(abs_db_path("phishguard.db")) as conn:
            scan_count = conn.execute(
                "SELECT COUNT(*) FROM scan_records"
            ).fetchone()[0]
            try:
                user_count = conn.execute(
                    "SELECT COUNT(*) FROM users"
                ).fetchone()[0]
            except Exception:
                pass
    except Exception:
        pass
    try:
        with db_conn(abs_db_path(settings.FEEDBACK_DB)) as conn:
            feedback_count = conn.execute(
                "SELECT COUNT(*) FROM feedback"
            ).fetchone()[0]
    except Exception:
        pass

    return {
        "uptime":        uptime_str,
        "uptime_seconds": uptime_s,
        "cpu": {
            "percent": cpu_pct,
            "available": cpu_pct is not None,
        },
        "memory": {
            "percent":   mem_pct,
            "used_mb":   mem_used_mb,
            "total_mb":  mem_total_mb,
            "available": mem_pct is not None,
        },
        "disk": {
            "percent":   disk_pct,
            "used_gb":   disk_used_gb,
            "total_gb":  disk_total_gb,
            "available": disk_pct is not None,
        },
        "files_kb":     files,
        "audit_entries": audit_entries,
        "db_rows": {
            "scans":    scan_count,
            "feedback": feedback_count,
            "users":    user_count,
        },
        "models": {
            "ensemble_loaded": models_loaded,
            "meta_learner_active": meta_active,
            "meta_version":    meta_version,
            "device":          str(engine.DEVICE) if hasattr(engine, "DEVICE") else "unknown",
        },
    }
