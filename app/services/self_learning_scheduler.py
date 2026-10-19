"""
Self-learning scheduler — runs training loops on a schedule.

Uses threading.Timer (no APScheduler dependency). Started from FastAPI lifespan.

Schedule:
  Weekly:     Meta-learner retrain (fast, ~2 min)
  Monthly:    LoRA fine-tuning (moderate, ~30 min)
  Quarterly:  Alert to run full retrain (manual)
"""
import os
import threading
import time
from datetime import datetime, timedelta

_scheduler = None
_started = False


class SelfLearningScheduler:
    """Timer-based scheduler for self-learning tasks."""

    def __init__(self):
        self._stop_event = threading.Event()
        self._thread = None
        now = datetime.utcnow()
        self._last_meta = now   # don't trigger immediately on start
        self._last_lora = now
        self._last_full = now
        self._running = False
        self._started = False

    def start(self):
        """Start the background scheduler thread."""
        if self._started:
            return
        self._stop_event.clear()
        self._started = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="self-learning-scheduler")
        self._thread.start()
        print("[SCHEDULER] Self-learning scheduler started.")

    def stop(self):
        """Stop the scheduler."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._started = False
        print("[SCHEDULER] Self-learning scheduler stopped.")

    def _run(self):
        """Background loop — checks every hour what needs to run."""
        while not self._stop_event.is_set():
            self._check_and_run()
            # Sleep 1 hour, but check every 60s for stop signal
            for _ in range(60):
                if self._stop_event.is_set():
                    return
                time.sleep(60)

    def _check_and_run(self):
        """Check schedule and run tasks that are due."""
        now = datetime.utcnow()

        # Weekly meta-learner retrain (every 7 days)
        if self._last_meta is None or (now - self._last_meta) >= timedelta(days=7):
            self._run_meta_retrain()
            self._last_meta = now

        # Monthly LoRA fine-tune (every 30 days)
        if self._last_lora is None or (now - self._last_lora) >= timedelta(days=30):
            self._run_lora_finetune()
            self._last_lora = now

        # Quarterly full retrain alert (every 90 days)
        if self._last_full is None or (now - self._last_full) >= timedelta(days=90):
            print("[SCHEDULER] Quarterly full retrain recommended. "
                  "Run: POST /api/v1/admin/retrain/full")
            self._last_full = now

    def _run_meta_retrain(self):
        """Run meta-learner retrain in background."""
        if self._running:
            print("[SCHEDULER] Training already in progress, skipping meta-learner retrain.")
            return
        self._running = True
        try:
            print(f"[SCHEDULER] Starting scheduled meta-learner retrain at {datetime.utcnow()}")
            from app.services.model_retrainer import retrain_meta
            retrain_meta()
            print("[SCHEDULER] Scheduled meta-learner retrain complete.")
        except Exception as e:
            print(f"[SCHEDULER] Meta-learner retrain error: {e}")
        finally:
            self._running = False

    def _run_lora_finetune(self):
        """Run LoRA fine-tuning in background."""
        if self._running:
            print("[SCHEDULER] Training already in progress, skipping LoRA fine-tune.")
            return
        self._running = True
        try:
            print(f"[SCHEDULER] Starting scheduled LoRA fine-tune at {datetime.utcnow()}")
            import subprocess
            import sys
            result = subprocess.run(
                [sys.executable, "train_lora_adapters.py", "--epochs", "2"],
                capture_output=True, text=True, timeout=3600,
            )
            if result.returncode == 0:
                print("[SCHEDULER] LoRA fine-tune complete.")
                # Reload models to pick up new adapters
                from app.services.ensemble_engine import load_all_models
                load_all_models()
            else:
                print(f"[SCHEDULER] LoRA fine-tune failed: {result.stderr[:500]}")
        except Exception as e:
            print(f"[SCHEDULER] LoRA fine-tune error: {e}")
        finally:
            self._running = False

    def status(self) -> dict:
        """Return current scheduler status."""
        return {
            "running": self._started,
            "last_meta_retrain": self._last_meta.isoformat() if self._last_meta else None,
            "last_lora_finetune": self._last_lora.isoformat() if self._last_lora else None,
            "last_full_retrain": self._last_full.isoformat() if self._last_full else None,
            "next_meta_retrain": (
                (self._last_meta + timedelta(days=7)).isoformat()
                if self._last_meta else "on first run"
            ),
            "next_lora_finetune": (
                (self._last_lora + timedelta(days=30)).isoformat()
                if self._last_lora else "on first run"
            ),
            "next_full_retrain": (
                (self._last_full + timedelta(days=90)).isoformat()
                if self._last_full else "on first run"
            ),
        }


def get_scheduler() -> SelfLearningScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = SelfLearningScheduler()
    return _scheduler


def start_scheduler():
    get_scheduler().start()


def stop_scheduler():
    get_scheduler().stop()
