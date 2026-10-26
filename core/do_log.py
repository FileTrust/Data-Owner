# do_log.py — logging, status, and dialog helpers.
# Reads UI widgets from do_state at call time (safe: widgets exist before any log call).

import atexit
import datetime
import os
import threading
import tkinter as tk
from pathlib import Path

import customtkinter as ctk

from . import do_state as S

# ── palette (kept in sync with do_ui tokens) ──────────────────────────────────
_BG  = "#1F2641"; _SRF = "#2A3355"; _ACC = "#FFD700"; _ACH = "#e6c200"
_T1  = "#FFFFFF"; _T2  = "#8899cc"; _MUT = "#3E497A"; _FNT = "Catamaran"
_RED = "#f87171"; _AMB = "#fde68a"; _SKY = "#7dd3fc"

# ── File logger ───────────────────────────────────────────────────────────────
_LOG_LOCK = threading.Lock()
_LOG_FILE = None


def _init_file_logger() -> None:
    global _LOG_FILE
    try:
        from .do_config import BASE_DIR  # imported here to avoid circular load order
        log_dir = Path(BASE_DIR) / "log"
        log_dir.mkdir(exist_ok=True)
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_path = log_dir / f"do_{date_str}.log"
        _LOG_FILE = open(log_path, "a", encoding="utf-8", buffering=1)  # line-buffered
        _write_raw(f"\n{'═' * 72}")
        _write_raw(f"  SESSION START  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _write_raw(f"{'═' * 72}")
        _start_log_archiver(log_dir)
    except Exception:
        _LOG_FILE = None


def _start_log_archiver(log_dir: Path) -> None:
    """Zip yesterday's logs and drop ones past their retention, then daily."""
    try:
        from . import log_archive
        from .do_config import config

        options = log_archive.options_from_config(config)
        log_archive.start_daily(
            log_dir,
            keep_days_by_name={"transactions": 90, "calls": 3},
            on_done=lambda s: s.get("rotated") and _write_raw(
                f"[log-archive] zipped {s['rotated']}, removed "
                f"{s['deleted_old'] + s['deleted_for_size']} old archive(s)"
            ),
            **options,
        )
    except Exception:
        pass  # tidying logs must never stop the app starting


def _close_file_logger() -> None:
    global _LOG_FILE
    if _LOG_FILE is not None:
        try:
            _write_raw(f"{'─' * 72}")
            _write_raw(f"  SESSION END    {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            _write_raw(f"{'─' * 72}\n")
            _LOG_FILE.close()
        except Exception:
            pass
        _LOG_FILE = None


atexit.register(_close_file_logger)


def _write_raw(line: str) -> None:
    if _LOG_FILE is None:
        return
    with _LOG_LOCK:
        try:
            _LOG_FILE.write(line + "\n")
        except Exception:
            pass


def _write_log(level: str, text: str, tag: str = "") -> None:
    if _LOG_FILE is None:
        return
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    tag_part = f"[{tag:<12}]  " if tag else "               "
    line = f"{ts}  {level:<8}  {tag_part}{text}"
    _write_raw(line)


def flog(tag: str, text: str, level: str = "INFO") -> None:
    """Write a structured entry to the log file only (not shown in UI panel)."""
    _write_log(level.upper(), text, tag)


# ── Status bar ────────────────────────────────────────────────────────────────
def set_status(text: str, mode: str = "ready"):
    if S.status_label is None:
        return
    if threading.current_thread() is not threading.main_thread():
        if S.root is not None:
            S.root.after(0, lambda t=text, m=mode: set_status(t, m))
        return

    colors = {
        "ready":   ("#FFD700", "#1F2641"),   # gold pill, dark navy text
        "running": ("#1e3a5f", "#93c5fd"),   # dark blue, light blue text
        "waiting": ("#78350f", "#fde68a"),   # dark amber, amber text
        "done":    ("#0c4a6e", "#7dd3fc"),   # dark sky, sky text
        "error":   ("#7f1d1d", "#fca5a5"),   # dark red, light red text
    }
    bg, fg = colors.get(mode, colors["ready"])
    S.status_var.set(text)
    S.status_label.configure(fg_color=bg, text_color=fg)
    try:
        S.status_label.update_idletasks()
        if S.root is not None:
            S.root.update_idletasks()
    except Exception:
        pass


def _echo_to_log_window(line: str) -> None:
    """Keep the pop-out log live. It is opened to watch, not to read a snapshot."""
    box = getattr(S, "log_window_text", None)
    if box is None:
        return
    try:
        box.insert("end", line if line.endswith("\n") else line + "\n")
        box.see("end")
    except Exception:
        S.log_window_text = None


def log(text: str, tag: str = "") -> None:
    # Move to the window's thread before doing anything at all. The file write
    # used to happen first and the whole call was then rescheduled, so every
    # line logged from a worker thread was written to the file twice -- with two
    # timestamps, which is exactly why it never read as a duplicate.
    if S.root is not None and threading.current_thread() is not threading.main_thread():
        try:
            S.root.after(0, lambda t=text, tg=tag: log(t, tg))
            return
        except Exception:
            pass  # the window is going away; still write the line below

    _write_log("INFO", text, tag)
    _echo_to_log_window(text)
    if S.result_text is None:
        return
    S.result_text.insert(tk.END, text + "\n")
    S.result_text.see(tk.END)


def _themed_dialog(title: str, message: str, kind: str = "error") -> None:
    """Themed modal dialog — replaces OS messagebox for error/warning/info."""
    accent = {"error": _RED, "warning": _AMB, "info": _ACC}.get(kind, _ACC)
    icon   = {"error": "✕", "warning": "⚠", "info": "ℹ"}.get(kind, "ℹ")

    root = S.root
    if root is None:
        return  # no UI yet — silently drop (already logged to file)

    dlg = tk.Toplevel(root)
    dlg.title(title)
    dlg.resizable(False, False)
    dlg.configure(bg=_BG)
    dlg.after(40, dlg.grab_set)

    card = ctk.CTkFrame(dlg, fg_color=_SRF, corner_radius=16)
    card.pack(padx=20, pady=20, fill="both", expand=True)

    # icon + title row
    hdr = ctk.CTkFrame(card, fg_color="transparent")
    hdr.pack(fill="x", padx=18, pady=(16, 6))

    ctk.CTkLabel(hdr, text=icon, font=(_FNT, 20), text_color=accent).pack(side="left", padx=(0, 10))
    ctk.CTkLabel(hdr, text=title, font=(_FNT, 13), text_color=_T1).pack(side="left")

    # separator
    ctk.CTkFrame(card, fg_color=_MUT, height=1, corner_radius=0).pack(fill="x", padx=18, pady=(0, 10))

    # message body
    ctk.CTkLabel(
        card, text=message,
        font=(_FNT, 11), text_color=_T2,
        wraplength=340, justify="left", anchor="w",
    ).pack(fill="x", padx=18, pady=(0, 16))

    # OK button
    ctk.CTkButton(
        card, text="OK", width=120, height=32,
        fg_color=_MUT, hover_color="#4a578e", text_color=_T1,
        font=(_FNT, 11), corner_radius=8,
        command=dlg.destroy,
    ).pack(pady=(0, 16))

    # centre over main window
    def _centre():
        dlg.update_idletasks()
        px = root.winfo_rootx() + (root.winfo_width()  - dlg.winfo_width())  // 2
        py = root.winfo_rooty() + (root.winfo_height() - dlg.winfo_height()) // 2
        dlg.wm_geometry(f"+{px}+{py}")

    dlg.after(10, _centre)


def _is_headless() -> bool:
    root = S.root
    return root is None or type(root).__name__ == "HeadlessRoot"


def _dispatch_dialog(level: str, title: str, message: str, kind: str) -> None:
    _write_log(level, f"{title}: {message}")
    if _LOG_FILE is None:
        try:
            print(f"[DO {level}] {title}: {message}", flush=True)
        except Exception:
            pass
    if S.root is None or _is_headless():
        return
    if threading.current_thread() is threading.main_thread():
        _themed_dialog(title, message, kind)
    else:
        S.root.after(0, lambda t=title, m=message, k=kind: _themed_dialog(t, m, k))


def show_error(title: str, message: str) -> None:
    _dispatch_dialog("ERROR", title, message, "error")


def show_info(title: str, message: str) -> None:
    if getattr(S, "auto_quiet_info", False):
        _write_log("INFO", f"{title}: {message}")
        return
    _dispatch_dialog("INFO", title, message, "info")


def show_warning(title: str, message: str) -> None:
    _dispatch_dialog("WARNING", title, message, "warning")


_LOG_STATE: dict = {}


def log_state(key: str, state, message: str, tag: str = "") -> None:
    """Log only when a repeated polling state changes."""
    if _LOG_STATE.get(key) != state:
        log(message, tag)
        _LOG_STATE[key] = state


def log_every(key: str, message: str, seconds: int = 30, tag: str = "") -> None:
    now = datetime.datetime.now().timestamp()
    last = S._LOG_LAST_TIME.get(key, 0.0)
    if now - last >= seconds:
        log(message, tag)
        S._LOG_LAST_TIME[key] = now
