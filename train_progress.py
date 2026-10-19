"""
Shared training progress tracking for PhishNot AI.
Used by both train_url_transformer.py and train_deberta_only.py
to report progress to the GUI.
"""

import os
import json
import time
import atexit

PROGRESS_FILE = os.path.join("models", "training_progress.json")
CONTROL_FILE  = os.path.join("models", "training_control.json")

# Clean up control file on script exit (no lingering "stop" from previous run)
def _cleanup_control():
    try:
        if os.path.exists(CONTROL_FILE):
            with open(CONTROL_FILE, 'r') as f:
                ctrl = json.load(f)
            # Only clean if it's leftover, not from current session
            if ctrl.get('action') == 'stop':
                os.remove(CONTROL_FILE)
    except:
        pass

atexit.register(_cleanup_control)


def read_control():
    """Check if GUI sent a pause/stop command. Returns 'none', 'pause', 'resume', 'stop'."""
    try:
        if os.path.exists(CONTROL_FILE):
            with open(CONTROL_FILE, 'r') as f:
                ctrl = json.load(f)
            return ctrl.get('action', 'none')
    except:
        pass
    return 'none'


def clear_control():
    """Clear the control file after processing a command."""
    try:
        if os.path.exists(CONTROL_FILE):
            os.remove(CONTROL_FILE)
    except:
        pass


def write_progress(script, epoch, total_epochs, batch, total_batches,
                   loss, status="training", extra=None):
    """Write current training state for GUI to read."""
    data = {
        "status":       status,
        "script":       script,
        "epoch":        epoch + 1,           # 1-based for display
        "total_epochs": total_epochs,
        "batch":        batch,
        "total_batches": total_batches,
        "loss":         loss,
        "timestamp":    time.time(),
    }
    if extra:
        data.update(extra)

    tmp = PROGRESS_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, PROGRESS_FILE)


def epoch_description_url(epoch_idx, total=4):
    """Human-readable description of what each URL epoch does for PhishNot."""
    descs = [
        "Learning basic URL patterns (length, special chars, domain structure)",
        "Refining phishing indicators (suspicious TLDs, encoded strings, typosquatting)",
        "Consolidating knowledge across diverse URL families and edge cases",
        "Final optimization — calibrating confidence scores for production",
    ]
    if 0 <= epoch_idx < len(descs):
        return descs[epoch_idx]
    return f"Epoch {epoch_idx + 1}/{total}"


def epoch_description_deberta(epoch_idx, total=4):
    """Human-readable description of what each DeBERTa epoch does for PhishNot."""
    descs = [
        "Learning email context (headers, body structure, intent detection)",
        "Detecting phishing language (urgency, impersonation, social engineering)",
        "Multi-class refinement (ham vs phishing vs spam decision boundaries)",
        "Final calibration — tuning ensemble weights for maximum accuracy",
    ]
    if 0 <= epoch_idx < len(descs):
        return descs[epoch_idx]
    return f"Epoch {epoch_idx + 1}/{total}"


def wait_if_paused():
    """
    If GUI sent 'pause', block training until 'resume' or 'stop'.
    Returns True if training should stop, False if it should continue.
    Also handles 'stop' by returning True.
    """
    while True:
        action = read_control()
        if action == 'stop':
            return True   # caller should exit
        elif action == 'pause':
            time.sleep(0.5)   # sleep 500ms and check again
            continue
        elif action in ('resume', 'none'):
            clear_control()
            return False   # continue training
        else:
            time.sleep(0.5)
            continue


def check_stop():
    """Check if a stop signal was received. Returns True if should stop."""
    action = read_control()
    if action == 'stop':
        return True
    return False
