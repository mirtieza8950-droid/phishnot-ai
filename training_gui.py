"""
PhishNot AI Training Monitor GUI
"""

import os
import sys
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import shutil

# ── Paths ────────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    EXE_DIR    = os.path.dirname(sys.executable)
    SCRIPT_DIR = os.path.dirname(EXE_DIR)
else:
    EXE_DIR    = os.path.dirname(os.path.abspath(__file__))
    SCRIPT_DIR = EXE_DIR

MODELS_DIR    = os.path.join(SCRIPT_DIR, "models")
PROGRESS_FILE = os.path.join(MODELS_DIR, "training_progress.json")
CONTROL_FILE  = os.path.join(MODELS_DIR, "training_control.json")
LOG_FILE      = os.path.join(MODELS_DIR, "gui_train.log")

def _find_python():
    for c in [
        r"D:\projects\Python\python.exe",
        os.path.join(SCRIPT_DIR, "..", "..", "Python", "python.exe"),
        shutil.which("python"),
    ]:
        if c and os.path.exists(c):
            return os.path.abspath(c)
    return "python"

PYTHON_EXE = _find_python()


def read_progress():
    try:
        if os.path.exists(PROGRESS_FILE):
            with open(PROGRESS_FILE, "r") as f:
                return json.load(f)
    except:
        pass
    return None


def write_control(action):
    try:
        os.makedirs(MODELS_DIR, exist_ok=True)
        tmp = CONTROL_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"action": action}, f)
        os.replace(tmp, CONTROL_FILE)
    except:
        pass


def format_time(seconds):
    if seconds < 0:
        return "--:--:--"
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


BG      = "#1e1e2e"
FG      = "#cdd6f4"
ACCENT  = "#89b4fa"
GREEN   = "#a6e3a1"
YELLOW  = "#f9e2af"
RED     = "#f38ba8"
SURFACE = "#313244"


class TrainingMonitor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishNot AI - Training Monitor")
        self.geometry("700x820")
        self.configure(bg=BG)

        self.process = None
        self.running = False
        self.paused  = False
        self.last_progress = None
        self.start_time = time.time()
        self.log_lines = []
        self._log_size = 0

        self._build_ui()
        self._poll()

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame",  background=BG)
        style.configure("TLabel",  background=BG, foreground=FG, font=("Consolas", 11))
        style.configure("Title.TLabel", background=BG, foreground=ACCENT, font=("Consolas", 14, "bold"))
        style.configure("Big.TLabel",   background=BG, foreground=GREEN, font=("Consolas", 32, "bold"))
        style.configure("Hint.TLabel",  background=BG, foreground="#6c7086", font=("Consolas", 9, "italic"))
        style.configure("Desc.TLabel",  background=SURFACE, foreground=FG, font=("Consolas", 10))

        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=20, pady=12)

        # Title
        ttk.Label(main, text="PhishNot AI Training Monitor", style="Title.TLabel").pack(anchor="w")
        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=(2, 8))

        # Launch
        ttk.Label(main, text="START TRAINING", style="Title.TLabel").pack(anchor="w")
        lf = tk.Frame(main, bg=SURFACE, bd=1, relief="solid")
        lf.pack(fill="x", pady=(2, 2))

        self.btn_url = tk.Button(
            lf, text="1.  URL Transformer  (run first)", bg=ACCENT, fg="#1e1e2e",
            activebackground="#74c7ec", font=("Consolas", 11, "bold"),
            bd=0, padx=12, pady=8, cursor="hand2",
            command=lambda: self._launch("url"))
        self.btn_url.pack(fill="x", padx=6, pady=(6, 3))

        self.btn_deberta = tk.Button(
            lf, text="2.  DeBERTa-v3-small  (run after URL)", bg=ACCENT, fg="#1e1e2e",
            activebackground="#74c7ec", font=("Consolas", 11, "bold"),
            bd=0, padx=12, pady=8, cursor="hand2",
            command=lambda: self._launch("deberta"))
        self.btn_deberta.pack(fill="x", padx=6, pady=(3, 6))

        ttk.Label(main, text="URL first (~3 h), then DeBERTa (~1.5 h).  Checkpoints survive reboots.",
                  style="Hint.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=2)

        # Status rows
        def _row(parent, lbl):
            f = tk.Frame(parent, bg=BG); f.pack(fill="x", pady=1)
            ttk.Label(f, text=lbl, style="TLabel", width=12).pack(side="left")
            var = tk.StringVar(value="-")
            ttk.Label(f, textvariable=var, style="TLabel").pack(side="left")
            return var

        self.status_var  = _row(main, "Status:")
        self.script_var  = _row(main, "Training:")
        self.epoch_var   = _row(main, "Epoch:")
        self.batch_var   = _row(main, "Batch:")

        # Find status label for color changes
        self.status_label = None
        for child in main.winfo_children():
            if isinstance(child, tk.Frame):
                children = child.winfo_children()
                if len(children) >= 2:
                    try:
                        if children[0].cget("text") == "Status:":
                            self.status_label = children[1]
                    except:
                        pass

        pf = tk.Frame(main, bg=BG); pf.pack(fill="x", pady=(6, 0))
        ttk.Label(pf, text="Progress:", style="TLabel", width=12).pack(side="left")
        self.pct_var = tk.StringVar(value="0.00 %")
        ttk.Label(pf, textvariable=self.pct_var, style="Big.TLabel").pack(side="left")

        self.progress_bar = ttk.Progressbar(main, length=620, mode="determinate")
        self.progress_bar.pack(fill="x", pady=3)

        self.loss_var    = _row(main, "Loss:")
        self.elapsed_var = _row(main, "Elapsed:")
        self.eta_var     = _row(main, "ETA:")

        # Epoch description
        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=6)
        ttk.Label(main, text="What this epoch does:", style="TLabel").pack(anchor="w")
        self.desc_var = tk.StringVar(value="Launch a training script above to begin.")
        df = tk.Frame(main, bg=SURFACE, bd=1, relief="solid")
        df.pack(fill="x", pady=(2, 6))
        ttk.Label(df, textvariable=self.desc_var, style="Desc.TLabel",
                  wraplength=640).pack(padx=8, pady=6)

        # Controls
        cf = tk.Frame(main, bg=SURFACE, bd=1, relief="solid")
        cf.pack(fill="x", pady=(0, 6))

        self.btn_pause = tk.Button(cf, text="PAUSE", bg=YELLOW, fg="#1e1e2e",
            font=("Consolas", 11, "bold"), bd=0, pady=7, state="disabled",
            command=self._on_pause, cursor="hand2")
        self.btn_pause.pack(side="left", padx=(6,3), pady=6, expand=True, fill="x")

        self.btn_resume = tk.Button(cf, text="RESUME", bg=GREEN, fg="#1e1e2e",
            font=("Consolas", 11, "bold"), bd=0, pady=7, state="disabled",
            command=self._on_resume, cursor="hand2")
        self.btn_resume.pack(side="left", padx=3, pady=6, expand=True, fill="x")

        self.btn_stop = tk.Button(cf, text="STOP", bg=RED, fg="#1e1e2e",
            font=("Consolas", 11, "bold"), bd=0, pady=7, state="disabled",
            command=self._on_stop, cursor="hand2")
        self.btn_stop.pack(side="left", padx=(3,6), pady=6, expand=True, fill="x")

        # Console output
        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=4)
        ttk.Label(main, text="Console Output:", style="TLabel").pack(anchor="w")
        self.console = tk.Text(main, height=7, bg="#11111b", fg="#a6adc8",
                               font=("Consolas", 9), insertbackground=FG,
                               state="disabled", wrap="word", relief="solid", bd=1)
        self.console.pack(fill="both", expand=True, pady=(2, 0))

    def _log(self, text):
        self.log_lines.append(text)
        self.console.configure(state="normal")
        self.console.insert("end", text + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    # ── Launch ────────────────────────────────────────────────────────────
    def _launch(self, script):
        if self.running:
            messagebox.showwarning("Already Running", "Stop the current training first.")
            return

        # Clear stale files
        for f in [CONTROL_FILE, PROGRESS_FILE, LOG_FILE]:
            try:
                if os.path.exists(f): os.remove(f)
            except: pass

        if script == "url":
            cmd = [PYTHON_EXE, "-u", "train_url_transformer.py"]
            desc = "URL Transformer (distilroberta-base) - binary phishing"
        else:
            cmd = [PYTHON_EXE, "-u", "train_deberta_only.py",
                   "--max-len", "128", "--epochs", "4"]
            desc = "DeBERTa-v3-small - 3-class (ham/phishing/spam)"

        self._log(f">>> {' '.join(cmd)}")
        self._log(f">>> cwd: {SCRIPT_DIR}")

        try:
            # Write a launcher script so stdout/stderr go to a log file
            # This avoids pipe-buffering issues with PyInstaller + subprocess
            launcher = os.path.join(MODELS_DIR, "_launcher.bat")
            with open(launcher, "w") as f:
                f.write(f'@echo off\ncd /d "{SCRIPT_DIR}"\n')
                f.write(f'"{cmd[0]}" {"".join(f" {a}" for a in cmd[1:])} > "{LOG_FILE}" 2>&1\n')

            self.process = subprocess.Popen(
                ["cmd", "/c", launcher],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )

            self.running    = True
            self.paused     = False
            self.start_time = time.time()

            self.status_var.set("TRAINING")
            self.script_var.set(desc)
            self.btn_pause.configure(state="normal")
            self.btn_stop.configure(state="normal")
            self.btn_resume.configure(state="disabled")
            self.btn_url.configure(state="disabled")
            self.btn_deberta.configure(state="disabled")

            self._log(f">>> Process started (PID {self.process.pid})")

            # Start log-file tailing thread
            threading.Thread(target=self._tail_log, daemon=True).start()

        except Exception as e:
            self._log(f"LAUNCH ERROR: {e}")
            messagebox.showerror("Launch Error", str(e))

    def _tail_log(self):
        """Tail the log file — writes from the training process arrive here."""
        # Wait for log file to appear
        for _ in range(60):
            if os.path.exists(LOG_FILE):
                break
            time.sleep(0.5)

        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                # Skip to end
                f.seek(0, 2)
                while self.process.poll() is None:
                    line = f.readline()
                    if line:
                        line = line.rstrip()
                        if line:
                            self.after(0, self._log, f"[TRAIN] {line}")
                    else:
                        time.sleep(0.5)
        except Exception as e:
            self.after(0, self._log, f"[TAIL ERROR] {e}")

        rc = self.process.returncode if self.process else -1
        self.after(0, self._log, f">>> Process exited (code {rc})")
        self.after(100, self._on_finished)

    def _on_finished(self):
        self.running = False
        self.btn_pause.configure(state="disabled")
        self.btn_resume.configure(state="disabled")
        self.btn_stop.configure(state="disabled")
        self.btn_url.configure(state="normal")
        self.btn_deberta.configure(state="normal")

        prog = read_progress()
        if prog:
            s = prog.get("status", "")
            if s == "stopped":
                self.status_var.set("STOPPED (checkpoint saved)")
            elif s in ("completed", "done"):
                self.status_var.set("COMPLETED")
            else:
                self.status_var.set(s.upper())
        else:
            self.status_var.set("FINISHED (check console below)")

    # ── Controls ──────────────────────────────────────────────────────────
    def _on_pause(self):
        if self.process and self.process.poll() is not None:
            self._on_finished()
            return
        write_control("pause")
        self.paused = True
        self.status_var.set("PAUSING...")
        self.btn_pause.configure(state="disabled")
        self.btn_resume.configure(state="normal")
        self._log(">>> PAUSE requested")

    def _on_resume(self):
        if self.process and self.process.poll() is not None:
            self._on_finished()
            return
        write_control("resume")
        self.paused = False
        self.status_var.set("TRAINING")
        self.btn_pause.configure(state="normal")
        self.btn_resume.configure(state="disabled")
        self._log(">>> RESUME requested")

    def _on_stop(self):
        if messagebox.askyesno("Stop Training", "Stop training? Progress is checkpointed."):
            if self.process and self.process.poll() is None:
                write_control("stop")
                self.status_var.set("STOPPING...")
                self._log(">>> STOP requested (waiting for process to exit...)")
            else:
                self._on_finished()
                return
            self.btn_stop.configure(state="disabled")
            self.btn_pause.configure(state="disabled")
            self.btn_resume.configure(state="disabled")

    # ── Poll ──────────────────────────────────────────────────────────────
    def _poll(self):
        # Safety: detect process exit even if tailing thread hasn't fired yet
        if self.running and self.process and self.process.poll() is not None:
            self.after(0, self._on_finished)
            self.after(500, self._poll)
            return

        prog = read_progress()
        if prog and prog != self.last_progress:
            self.last_progress = prog
            self._update(prog)
        elif self.running and not prog:
            self.status_var.set("TRAINING (loading...)")

        if self.running:
            self.elapsed_var.set(format_time(time.time() - self.start_time))
        self.after(500, self._poll)

    def _update(self, p):
        status   = p.get("status", "")
        epoch    = p.get("epoch", 0)
        total_ep = p.get("total_epochs", 4)
        batch    = p.get("batch", 0)
        total_b  = p.get("total_batches", 1)
        loss     = p.get("loss", 0)
        desc     = p.get("epoch_desc", "")

        smap = {"training":"TRAINING","paused":"PAUSED","stopped":"STOPPED",
                "epoch_complete":"EPOCH COMPLETE","completed":"COMPLETED"}
        self.status_var.set(smap.get(status, status.upper()))

        if self.status_label:
            colors = {"training":GREEN,"paused":YELLOW,"stopped":RED,
                      "epoch_complete":ACCENT}
            try:
                self.status_label.configure(foreground=colors.get(status, FG))
            except: pass

        self.epoch_var.set(f"{epoch} / {total_ep}")
        self.batch_var.set(f"{batch:,} / {total_b:,}")
        pct = (batch / total_b * 100) if total_b > 0 else 0
        self.pct_var.set(f"{pct:.2f} %")
        self.progress_bar["value"] = pct
        self.loss_var.set(f"{loss:.4f}")

        if batch > 0 and self.running:
            elapsed = time.time() - self.start_time
            self.eta_var.set(format_time((total_b - batch) * elapsed / batch))

        if desc:
            self.desc_var.set(desc)


if __name__ == "__main__":
    app = TrainingMonitor()
    app.mainloop()
