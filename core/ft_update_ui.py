"""Tk adapter: workers only perform I/O; Tk changes stay on its event loop."""
import json
import os
from pathlib import Path
import queue
import threading
import shlex
import subprocess
import sys
import time
import tkinter as tk
import webbrowser

from .ft_updates import Client, atomic_json


class UpdateNotice:
    def __init__(self, root, app_dir, busy=lambda: False):
        self.root, self.busy = root, busy
        self.client = Client(app_dir)
        self.results = queue.Queue()
        self.running = False
        self.pending = None
        self.popup = None
        self.preparation = None
        self.preparation_status = None
        self.app_dir = Path(app_dir).resolve()
        bar = tk.Menu(root)
        self.menu = tk.Menu(bar, tearoff=False)
        self.menu.add_command(label=f"Version {self.client.current}", state="disabled")
        self.menu.add_command(label="Check for updates", command=self.check)
        bar.add_cascade(label="Updates", menu=self.menu)
        root.configure(menu=bar)
        self.bar = bar
        root.after(500, self._poll)
        root.after(5000, lambda: self.check(manual=False))

    def check(self, manual=True):
        if self.running:
            return
        self.running = True

        def work():
            try:
                result = self.client.check(force=manual)
            except Exception:
                result = {"state": "unavailable", "message": "Update check unavailable. Check installation dependencies and GitHub access."}
            self.results.put((result, manual))

        threading.Thread(target=work, daemon=True, name="application-update-check").start()

    def _poll(self):
        if self.preparation and self.preparation.poll() is not None:
            if self.preparation_status is not None:
                self.preparation_status.set(
                    "Prepared. Finish your work and close the app, then run:\n" +
                    shlex.join([str(self.app_dir / ".venv/bin/python"), str(self.app_dir / "upgrade.py"), "apply"])
                    if self.preparation.returncode == 0 else
                    "Preparation failed. Your running app is unchanged. See .filetrust-updates/gui-preparation.log."
                )
            self.preparation = None
        try:
            while True:
                result, manual = self.results.get_nowait()
                self.running = False
                if result["state"] == "available":
                    self.bar.entryconfigure(1, label=f"Updates — {result['latest']} available")
                    self.pending = (result, manual)
                elif manual:
                    self._show(result)
        except queue.Empty:
            pass
        if self.pending:
            result, manual = self.pending
            if manual or (not self.busy() and self.root.state() == "normal"):
                self.pending = None
                if manual or self._may_notify(result["latest"]):
                    self._show(result)
        self.root.after(500, self._poll)

    def _may_notify(self, latest):
        path = self.client.state_dir / "notice.json"
        try:
            notice = json.loads(path.read_text())
        except (OSError, ValueError):
            notice = {}
        if notice.get("version") == latest and notice.get("after", 0) > time.time():
            return False
        atomic_json(path, {"version": latest, "after": time.time() + 24 * 3600})
        return True

    def _show(self, result):
        if self.popup and self.popup.winfo_exists():
            return
        window = self.popup = tk.Toplevel(self.root)
        window.title("FileTrust application updates")
        window.transient(self.root)
        if result["state"] == "available":
            body = (f"Installed: {result['current']}\nAvailable: {result['latest']}\n\n"
                    f"{result.get('notes', '')}\n\nPrepare downloads and checks the update, if supported.\n"
                    "Finish work and close the app before installation.\n"
                    "Your running app will not be changed automatically.")
            if os.environ.get('FILETRUST_CONTAINER') == '1':
                body = (f"Installed: {result['current']}\nAvailable: {result['latest']}\n\n"
                        "Finish work, then update from the host checkout:\n"
                        "git pull --ff-only\n./docker.sh update\n\n"
                        "The application will not replace its own container.")
        elif result["state"] == "current":
            body = f"Version {self.client.current}: no newer release in your selected channel."
        else:
            body = result.get("message", "Update information has not been verified yet.")
        tk.Label(window, text=body, justify="left", wraplength=460, padx=20, pady=16).pack()
        self.preparation_status = tk.StringVar(value="")
        tk.Label(window, textvariable=self.preparation_status, justify="left", wraplength=460, padx=20).pack()
        controls = tk.Frame(window)
        controls.pack(padx=20, pady=(0, 15))
        if result.get("release_url") and result["state"] == "available" and os.environ.get('FILETRUST_CONTAINER') != '1':
            if result.get("installable") and sys.platform == "linux":
                tk.Button(controls, text="Prepare update", command=self._prepare).pack(side="left", padx=5)
            tk.Button(controls, text="View release", command=lambda: webbrowser.open(result["release_url"])).pack(side="left", padx=5)
        tk.Button(controls, text="Later" if result["state"] == "available" else "Close", command=window.destroy).pack(side="left", padx=5)

    def _prepare(self):
        if os.environ.get('FILETRUST_CONTAINER') == '1':
            self.preparation_status.set('Use ./docker.sh update from the host checkout. No code changed.')
            return
        if self.preparation:
            return
        try:
            directory = self.app_dir / ".filetrust-updates"
            directory.mkdir(mode=0o755, exist_ok=True)
            if directory.is_symlink():
                raise ValueError("Invalid update directory")
            descriptor = os.open(directory / "gui-preparation.log", os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as log:
                self.preparation = subprocess.Popen([sys.executable, str(self.app_dir / "upgrade.py"), "prepare"], stdout=log, stderr=subprocess.STDOUT)
            self.preparation_status.set("Preparing the update in the background. Your current work continues.")
        except Exception:
            self.preparation_status.set("Could not start preparation. Use upgrade.py prepare from a terminal.")

    def daily(self):
        self.check(manual=False)
        self.root.after(3600 * 1000, self.daily)


def attach(root, app_dir, busy=lambda: False):
    try:
        notice = UpdateNotice(root, app_dir, busy)
        root._filetrust_updates = notice
        root.after(3600 * 1000, notice.daily)
        return notice
    except Exception:
        # A missing optional update dependency must not prevent wallet access.
        return None
