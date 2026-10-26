# do_panels.py — the log and the pieces list, as windows of their own.
#
# They are not on the dashboard at all. Two panels took the bottom half of a
# window whose job is to accept a file, and the progress bar now says what is
# happening without them. Opened from the tray or from the header buttons,
# resizable, and fine on a second screen.
#
# The log window opens with history already in it. Opening a live tail and
# starting from blank hides the very thing you opened it to see -- what just
# happened -- so it seeds from today's log file and follows from there.

from __future__ import annotations

import datetime
from pathlib import Path

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk

from . import do_actions as A
from . import do_state as S

_BASE = "#232840"
_SURFACE = "#2A3355"
_ACCENT = "#FFD700"
_TXT1 = "#E6ECFF"
_TXT2 = "#8899cc"
_MUTED = "#3E497A"
_FONT = "Segoe UI"

SEED_LINES = 200


def _today_log_path() -> Path | None:
    try:
        from .do_config import BASE_DIR
        return Path(BASE_DIR) / "log" / f"do_{datetime.datetime.now():%Y-%m-%d}.log"
    except Exception:
        return None


def _recent_log_text(limit: int = SEED_LINES) -> str:
    path = _today_log_path()
    if path is None or not path.is_file():
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return ""
    return "".join(lines[-limit:])


def _place(window: ctk.CTkToplevel, title: str, size: str) -> None:
    window.title(title)
    window.geometry(size)
    window.configure(fg_color=_BASE)
    try:
        window.transient(S.root)
    except Exception:
        pass


def open_log_window() -> None:
    """The network log, large, seeded with what already happened."""
    existing = getattr(S, "log_window", None)
    if existing is not None and existing.winfo_exists():
        existing.deiconify()
        existing.lift()
        return

    window = ctk.CTkToplevel(S.root)
    _place(window, "FileTrust — Network Results", "900x560")
    window.grid_rowconfigure(1, weight=1)
    window.grid_columnconfigure(0, weight=1)

    header = ctk.CTkFrame(window, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
    header.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(
        header, text="Network Results", font=(_FONT, 13), text_color=_ACCENT,
    ).grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(
        header, text=f"last {SEED_LINES} lines, then live",
        font=(_FONT, 9), text_color=_TXT2,
    ).grid(row=1, column=0, sticky="w")

    text = ctk.CTkTextbox(
        window, corner_radius=8, font=("Consolas", 10),
        text_color=_TXT1, fg_color=_SURFACE, border_width=1, border_color=_MUTED,
    )
    text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 12))
    seed = _recent_log_text()
    if seed:
        text.insert("1.0", seed)
    else:
        text.insert("1.0", "(no log for today yet)\n")
    text.see("end")

    ctk.CTkButton(
        header, text="Clear", width=70, height=26,
        fg_color=_MUTED, hover_color=_ACCENT, text_color=_TXT1,
        font=(_FONT, 10), corner_radius=8,
        command=lambda: text.delete("1.0", "end"),
    ).grid(row=0, column=1, rowspan=2, sticky="e")

    S.log_window = window
    S.log_window_text = text

    def closed() -> None:
        S.log_window_text = None
        S.log_window = None
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", closed)


def open_pieces_window() -> None:
    """The pieces on this computer, in a window with room for long names."""
    existing = getattr(S, "pieces_window", None)
    if existing is not None and existing.winfo_exists():
        existing.deiconify()
        existing.lift()
        return

    window = ctk.CTkToplevel(S.root)
    _place(window, "FileTrust — Pieces Directory", "620x460")
    window.grid_rowconfigure(1, weight=1)
    window.grid_columnconfigure(0, weight=1)

    header = ctk.CTkFrame(window, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
    header.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(
        header, text="Pieces Directory", font=(_FONT, 13), text_color=_ACCENT,
    ).grid(row=0, column=0, sticky="w")
    ctk.CTkButton(
        header, text="Refresh", width=80, height=26,
        fg_color=_MUTED, hover_color=_ACCENT, text_color=_TXT1,
        font=(_FONT, 10), corner_radius=8,
        command=A.refresh_pieces_list,
    ).grid(row=0, column=1, sticky="e")

    frame = ctk.CTkFrame(window, fg_color="transparent")
    frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 12))
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    tree = ttk.Treeview(frame, columns=("name", "size"), show="headings",
                        style="Pieces.Treeview")
    tree.heading("name", text="Piece file")
    tree.heading("size", text="Size")
    tree.column("name", width=420, stretch=True)
    tree.column("size", width=110, anchor="e", stretch=False)
    tree.grid(row=0, column=0, sticky="nsew")
    scroll = ctk.CTkScrollbar(frame, orientation="vertical", command=tree.yview,
                              fg_color=_SURFACE, button_color=_MUTED,
                              button_hover_color=_ACCENT)
    tree.configure(yscrollcommand=scroll.set)
    scroll.grid(row=0, column=1, sticky="ns")

    S.pieces_window = window
    S.pieces_window_tree = tree
    A.refresh_pieces_list()

    def closed() -> None:
        S.pieces_window_tree = None
        S.pieces_window = None
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", closed)


# ── About ─────────────────────────────────────────────────────────────────────
# A window rather than a message box, so the addresses are links you can click
# and the licence has room to be stated rather than abbreviated.

ABOUT_TITLE = "FileTrust Data Owner"
ABOUT_SUBTITLE = "Decentralised File Protection"
ABOUT_BODY = (
    "Splits a file into pieces, spreads them over independent Vault Keepers, "
    "and keeps the key in the hands of Guardians you choose. No single machine "
    "holds your file, and no single party can read it."
)
ABOUT_LINKS = (
    ("Electra Sphere Innovations", "https://electrasi.es"),
    ("FileTrust", "https://filetrust.io"),
)
ABOUT_COPYRIGHT = "Copyright 2026 Electra Sphere Innovations. All rights reserved."
ABOUT_LICENCE = (
    "Licensed under the Functional Source License 1.1 (FSL-1.1-ALv2): free to "
    "read, run and change for any purpose, including inside a company, and not "
    "for building a competing product. Each release also becomes Apache-2.0 two "
    "years after it is published. The full terms are in the LICENSE file."
)


def logo_path() -> Path | None:
    path = Path(__file__).resolve().parent / "assets" / "logo.png"
    return path if path.is_file() else None


def _logo_image(size: int):
    """The FileTrust mark, or None when Pillow is missing.

    A missing logo is never a reason to withhold the window it sits in, so
    every caller treats None as "no picture" and carries on.
    """
    path = logo_path()
    if path is None:
        return None
    try:
        from PIL import Image
        return ctk.CTkImage(
            light_image=Image.open(path), dark_image=Image.open(path),
            size=(size, size),
        )
    except Exception:
        return None


def _link_label(parent, text: str, url: str):
    """A label that looks like a link and opens one."""
    import webbrowser

    label = ctk.CTkLabel(
        parent, text=text, font=(_FONT, 11, "underline"), text_color=_ACCENT,
        cursor="hand2",
    )
    label.bind("<Button-1>", lambda _event: webbrowser.open_new_tab(url))
    # The address itself, so nobody has to click to find out where it goes.
    _tooltip(label, url)
    return label


def _tooltip(widget, text: str) -> None:
    state: dict = {"window": None}

    def show(_event=None):
        if state["window"] is not None:
            return
        window = tk.Toplevel(widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(
            f"+{widget.winfo_rootx()}+{widget.winfo_rooty() + widget.winfo_height() + 4}"
        )
        tk.Label(window, text=text, bg="#1e293b", fg="white",
                 padx=8, pady=4, font=(_FONT, 9)).pack()
        state["window"] = window

    def hide(_event=None):
        window = state.get("window")
        if window is not None:
            window.destroy()
            state["window"] = None

    widget.bind("<Enter>", show, add="+")
    widget.bind("<Leave>", hide, add="+")


def open_about_window() -> None:
    existing = getattr(S, "about_window", None)
    if existing is not None and existing.winfo_exists():
        existing.deiconify()
        existing.lift()
        return

    window = ctk.CTkToplevel(S.root)
    _place(window, "About FileTrust", "520x400")
    window.grid_columnconfigure(0, weight=1)
    window.resizable(False, False)

    body = ctk.CTkFrame(window, fg_color=_SURFACE, corner_radius=12)
    body.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
    body.grid_columnconfigure(0, weight=1)

    # The mark, then the name: the logo is the first thing an About window
    # should settle, and it carries the brand the licence line names.
    title_row = ctk.CTkFrame(body, fg_color="transparent")
    title_row.grid(row=0, column=0, sticky="w", padx=18, pady=(18, 10))
    logo = _logo_image(64)
    if logo is not None:
        ctk.CTkLabel(title_row, image=logo, text="").pack(side="left", padx=(0, 14))
        title_row.logo = logo   # CTkImage must outlive this function
    names = ctk.CTkFrame(title_row, fg_color="transparent")
    names.pack(side="left")
    ctk.CTkLabel(
        names, text=ABOUT_TITLE, font=(_FONT, 18), text_color=_TXT1,
    ).pack(anchor="w")
    ctk.CTkLabel(
        names, text=ABOUT_SUBTITLE, font=(_FONT, 11), text_color=_ACCENT,
    ).pack(anchor="w")
    ctk.CTkLabel(
        body, text=ABOUT_BODY, font=(_FONT, 11), text_color=_TXT1,
        wraplength=430, justify="left",
    ).grid(row=2, column=0, sticky="w", padx=18)

    links = ctk.CTkFrame(body, fg_color="transparent")
    links.grid(row=3, column=0, sticky="w", padx=18, pady=(14, 10))
    ctk.CTkLabel(
        links, text="A product of", font=(_FONT, 11), text_color=_TXT2,
    ).pack(side="left", padx=(0, 6))
    _link_label(links, *ABOUT_LINKS[0]).pack(side="left", padx=(0, 10))
    _link_label(links, *ABOUT_LINKS[1]).pack(side="left")

    ctk.CTkLabel(
        body, text=ABOUT_COPYRIGHT, font=(_FONT, 10), text_color=_TXT2,
        wraplength=430, justify="left",
    ).grid(row=4, column=0, sticky="w", padx=18)
    ctk.CTkLabel(
        body, text=ABOUT_LICENCE, font=(_FONT, 10), text_color=_TXT2,
        wraplength=430, justify="left",
    ).grid(row=5, column=0, sticky="w", padx=18, pady=(6, 14))

    ctk.CTkButton(
        body, text="Close", width=90, height=28,
        fg_color=_MUTED, hover_color=_ACCENT, text_color=_TXT1,
        font=(_FONT, 10), corner_radius=8, command=window.destroy,
    ).grid(row=6, column=0, sticky="e", padx=18, pady=(0, 16))

    S.about_window = window

    def closed() -> None:
        S.about_window = None
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", closed)
