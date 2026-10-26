# do_ui.py — build_ui() and helpers.
# Builds the entire CustomTkinter / Tkinter GUI, storing all widgets in do_state (S).

import datetime
import os
import threading
import time
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import customtkinter as ctk

from . import do_config as C
from . import do_state as S
from . import do_log as L
from . import do_records as R
from . import do_chain as CH
from . import do_vaultmesh as VM
from . import do_network as N
from . import do_actions as A
from . import do_tray as T

# ── design tokens — FileTrust palette ─────────────────────────────────────────
_BG        = "#1F2641"   # window shell        — deep navy
_SURFACE   = "#2A3355"   # card surface        — medium navy
_BASE      = "#232840"   # textbox / table bg  — darkest navy
_ACCENT    = "#FFD700"   # gold                — FileTrust primary accent
_ACCENT_H  = "#e6c200"   # gold darker         — hover
_ACCENT_S  = "#2f3a5e"   # soft navy           — secondary button bg
_ACCENT_SH = "#374468"   # soft navy hover
_TXT1      = "#FFFFFF"   # white               — primary text
_TXT2      = "#8899cc"   # muted blue-gray     — secondary / labels
_MUTED     = "#3E497A"   # medium navy-purple  — borders / icon-btn bg
_MUTED_H   = "#4a578e"   # slightly lighter    — icon-btn hover
_FONT      = "Catamaran" # FileTrust brand font (falls back to system sans)


def _make_autoscroll(sb, orient: str):
    """
    Returns a yscrollcommand/xscrollcommand callback.
    The scrollbar overlays the content via place() — appears only when needed,
    disappears when all content is visible, and never affects the grid layout.
    """
    def _set(first, last):
        if float(first) <= 0.0 and float(last) >= 1.0:
            sb.place_forget()
        else:
            if not sb.winfo_ismapped():
                if orient == "vertical":
                    sb.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne")
                else:
                    sb.place(relx=0.0, rely=1.0, relwidth=1.0, anchor="sw")
        sb.set(first, last)
    return _set


def _add_tooltip(widget, text: str) -> None:
    tip = {"window": None}

    def show(_event=None):
        if tip["window"] is not None:
            return
        x = widget.winfo_rootx() + widget.winfo_width() + 8
        y = widget.winfo_rooty() + widget.winfo_height() // 2
        window = tk.Toplevel(widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(f"+{x}+{y}")
        tk.Label(
            window, text=text,
            bg="#1e293b", fg="white",
            padx=8, pady=4, font=(_FONT, 9),
        ).pack()
        tip["window"] = window

    def hide(_event=None):
        w = tip.get("window")
        if w:
            w.destroy()
            tip["window"] = None

    widget.bind("<Enter>", show, add="+")
    widget.bind("<Leave>", hide, add="+")
    widget.bind("<ButtonPress>", hide, add="+")


def _icon_btn(parent, text, command, tooltip="", width=30, height=26, soft=False):
    """Small square icon button. soft=True uses the accent-tinted palette."""
    bg  = _ACCENT_S  if soft else _MUTED
    hov = _ACCENT_SH if soft else _MUTED_H
    fg  = _ACCENT    if soft else _TXT1
    btn = ctk.CTkButton(
        parent, text=text, command=command,
        width=width, height=height,
        fg_color=bg, hover_color=hov, text_color=fg,
        font=(_FONT, 12), corner_radius=8,
    )
    if tooltip:
        _add_tooltip(btn, tooltip)
    return btn


def _section_label(parent, text):
    return ctk.CTkLabel(parent, text=text, font=(_FONT, 11), text_color=_ACCENT)


def _first_drop_file(event_data: str) -> str:
    try:
        files = S.root.tk.splitlist(event_data)
    except tk.TclError:
        files = [event_data]
    return files[0] if files else ""


def _make_root():
    if os.environ.get("FILETRUST_DISABLE_DND") == "1":
        return ctk.CTk()

    try:
        from tkinterdnd2 import TkinterDnD

        class CTkDnD(ctk.CTk, TkinterDnD.DnDWrapper):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.TkdndVersion = TkinterDnD.require(self)

        return CTkDnD()
    except Exception:
        return ctk.CTk()


def _register_file_drop(widget, on_drop, on_enter=None, on_leave=None) -> bool:
    if os.environ.get("FILETRUST_DISABLE_DND") == "1":
        return False

    try:
        from tkinterdnd2 import COPY, DND_FILES

        widget.drop_target_register(DND_FILES)
        if on_enter is not None:
            widget.dnd_bind("<<DropEnter>>", lambda event: (on_enter(), COPY)[1])
        if on_leave is not None:
            widget.dnd_bind("<<DropLeave>>", lambda event: (on_leave(), COPY)[1])
        widget.dnd_bind("<<Drop>>", lambda event: (on_drop(event.data), COPY)[1])
        return True
    except Exception:
        return False


# ── Your account ──────────────────────────────────────────────────────────────
# The address is derived from the private key at startup, so this is the
# identity the app actually signs with -- there is no stored copy that could
# be showing something else.


def _account_balance_text() -> str:
    try:
        wei = int(C.w3.eth.get_balance(C.DO))
    except Exception:
        return "balance unavailable"
    if wei == 0:
        return "0 FTU — needs funds before uploading"
    return f"{wei / 10 ** 18:,.4f} FTU"


_balance_text = "checking balance…"
_balance_fetching = False


def _poll_balance() -> None:
    """Copy whatever the worker has written onto the label. Window thread only.

    Polling stops as soon as the answer is in, so an idle window schedules
    nothing: handing the value back with `after` from the worker is not safe --
    `after` is itself a Tcl call, and a scheduled update was observed never
    arriving.
    """
    root = S.root
    if root is None:
        return
    if S.account_balance_var is not None:
        S.account_balance_var.set(_balance_text)
    if _balance_fetching:
        root.after(400, _poll_balance)


def refresh_account_balance() -> None:
    """Read the balance once, on a worker. Called at start-up and by the button.

    Not on a timer: a balance only changes when this account spends or is paid,
    and a window left open all day would otherwise keep asking a node that has
    nothing new to say.
    """
    global _balance_fetching
    if _balance_fetching:
        return
    _balance_fetching = True
    if S.account_balance_var is not None:
        S.account_balance_var.set("checking…")

    def work() -> None:
        global _balance_text, _balance_fetching
        try:
            _balance_text = _account_balance_text()
        finally:
            _balance_fetching = False

    threading.Thread(target=work, daemon=True, name="balance").start()
    _poll_balance()


def _build_account_row(parent, row: int) -> None:
    """Show this app's own address, with a copy button, and its balance.

    A user who let install.sh create the account sees the address once, in
    terminal output that scrolls away, and the app never showed it again. The
    address is derived from the key here, so what is on screen is always the
    identity actually signing.
    """
    box = ctk.CTkFrame(parent, fg_color="transparent")
    box.grid(row=row, column=0, sticky="w", pady=(8, 0))

    ctk.CTkLabel(
        box, text="Your address", font=(_FONT, 10), text_color=_TXT2,
    ).pack(side="left")
    ctk.CTkLabel(
        box, text=C.DO, font=(_FONT, 11), text_color=_TXT1,
    ).pack(side="left", padx=(8, 8))

    copy_button = ctk.CTkButton(
        box, text="Copy", width=60, height=24,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8,
    )

    def _copy() -> None:
        root = S.root
        if root is None:
            return
        root.clipboard_clear()
        root.clipboard_append(C.DO)
        # Confirm it happened: a clipboard write is otherwise invisible, and a
        # user who is not sure clicks again and again.
        copy_button.configure(text="Copied")
        root.after(1500, lambda: copy_button.configure(text="Copy"))

    copy_button.configure(command=_copy)
    copy_button.pack(side="left")

    S.account_balance_var = tk.StringVar(value="checking balance…")
    ctk.CTkLabel(
        box, textvariable=S.account_balance_var,
        font=(_FONT, 10), text_color=_TXT2,
    ).pack(side="left", padx=(14, 4))
    _icon_btn(
        box, "\u21bb", refresh_account_balance,
        tooltip="Check the balance again", width=26, height=22, soft=True,
    ).pack(side="left")
    refresh_account_balance()


def build_ui():
    L._init_file_logger()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    S.root = _make_root()
    S.root.title("FileTrust • Data Owner Interface")
    S.root.geometry("1280x860")
    S.root.minsize(1100, 700)
    S.root.configure(fg_color=_BG)

    # The window's own icon, so the task bar and the title bar carry the mark.
    try:
        from PIL import ImageTk, Image
        _logo = Path(__file__).resolve().parent / "assets" / "logo.png"
        if _logo.is_file():
            S.root._window_icon = ImageTk.PhotoImage(Image.open(_logo))
            S.root.iconphoto(True, S.root._window_icon)
    except Exception:
        pass

    main = ctk.CTkFrame(S.root, corner_radius=20, fg_color=_BASE)
    main.pack(fill="both", expand=True, padx=20, pady=20)
    main.grid_rowconfigure(2, weight=1)
    main.grid_columnconfigure(0, weight=1)

    # ── Header ──────────────────────────────────────────────────────────────────
    header = ctk.CTkFrame(main, fg_color="transparent")
    # 44: the tab below insets its cards by 10, and each card insets its first
    # label by another 14. Measured rather than guessed -- the title sat at 40
    # while every row of the form began at 64.
    header.grid(row=0, column=0, sticky="ew", padx=44, pady=(16, 10))
    header.grid_columnconfigure(0, weight=1)

    ctk.CTkLabel(
        header, text="Data Owner Dashboard",
        font=(_FONT, 20), text_color=_TXT1,
    ).grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(
        header, text="FileTrust · Decentralised File Protection",
        font=(_FONT, 10), text_color=_TXT2,
    ).grid(row=1, column=0, sticky="w")
    _build_account_row(header, 2)

    # Upload controls — fixed in top-right corner, visible on every tab
    upload_controls = ctk.CTkFrame(header, fg_color="transparent")
    upload_controls.grid(row=0, column=1, rowspan=2, sticky="e", padx=(16, 0))
    S.auto_select_var = tk.BooleanVar(value=True)

    def _auto_select_changed():
        A.schedule_latest_upload_settings_save()
        if S.auto_select_var is not None and S.auto_select_var.get():
            A.apply_auto_selection_from_latest(show_errors=True)

    ctk.CTkSwitch(
        upload_controls, text="Auto-select Guardians and Keepers",
        variable=S.auto_select_var,
        font=(_FONT, 10), text_color=_TXT1,
        progress_color=_ACCENT, button_color=_TXT1, button_hover_color=_ACCENT_H,
        switch_height=16, switch_width=36,
        command=_auto_select_changed,
    ).pack(side="left", padx=(0, 10))
    # No "Save Setup": every field here already saves itself as you type, so the
    # button only wrote a log line and implied the rest was unsaved.
    #
    # No pause/play either. Its two jobs are gone: continuing an interrupted
    # upload is offered on start-up and resumes from the exact byte, and the
    # pause itself was a control whose only remaining use was stopping a
    # transfer the app will finish by itself.

    S.upload_button = ctk.CTkButton(
        upload_controls, text="⬆  Upload File", width=150, height=46,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 12), corner_radius=10,
        command=lambda: threading.Thread(target=A.run_all, daemon=True).start(),
    )
    S.upload_button.pack(side="left")

    # ── shared ttk style (one Style object, applied before Treeviews are built) ─
    _style = ttk.Style(S.root)
    try:
        _style.theme_use("clam")
    except tk.TclError:
        pass

    def _tree_style(name):
        _style.configure(
            f"{name}.Treeview",
            background=_BASE, fieldbackground=_BASE, foreground=_TXT1,
            borderwidth=0, rowheight=26, font=(_FONT, 9),
        )
        _style.configure(
            f"{name}.Treeview.Heading",
            background=_MUTED, foreground=_TXT2,
            font=(_FONT, 9), relief="flat", padding=(4, 4),
        )
        _style.map(
            f"{name}.Treeview",
            background=[("selected", _ACCENT)],
            foreground=[("selected", "#1F2641")],
        )
        _style.layout(f"{name}.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    for _n in ("Guardian", "VK", "Pol", "ReqBook", "Pieces"):
        _tree_style(_n)
    _style.configure("Pieces.Treeview", rowheight=22, font=(_FONT, 9))  # compact for narrow panel

    # ── Tab view ────────────────────────────────────────────────────────────────
    # Above the tabs, because the Guardians tab's Create and Show Policy, and the
    # Requester tab's list, all act on this one name. They used to read a box
    # sitting on another tab, so you pressed Create without being able to see
    # what you were creating it for.
    policy_bar = ctk.CTkFrame(main, fg_color="transparent")

    ctk.CTkLabel(policy_bar, text="Policy Name", font=(_FONT, 11), text_color=_TXT2).grid(
        row=0, column=0, padx=(0, 8), pady=0, sticky="w"
    )
    S.entry_policy_name = ctk.CTkComboBox(
        policy_bar, width=220,
        values=A._policy_name_values(),
        command=lambda val: (A.refresh_file_id_preview(), N.load_policy_requesters_ui(),
                            A.refresh_policy_active_button(),
                            A.schedule_latest_upload_settings_save()),
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
        button_color=_MUTED, button_hover_color=_ACCENT,
        dropdown_fg_color=_SURFACE, dropdown_text_color=_TXT1,
        dropdown_hover_color=_MUTED,
    )
    S.entry_policy_name.grid(row=0, column=1, padx=0, pady=0, sticky="w")
    S.entry_policy_name.set("Policy01")
    S.entry_policy_name._entry.bind("<KeyRelease>", lambda e: (A.refresh_file_id_preview(), N.load_policy_requesters_ui(), A.schedule_latest_upload_settings_save()))

    tabview = ctk.CTkTabview(
        main,
        corner_radius=16,
        fg_color=_BASE,
        segmented_button_fg_color=_SURFACE,
        segmented_button_selected_color=_ACCENT,
        segmented_button_selected_hover_color=_ACCENT_H,
        segmented_button_unselected_color=_SURFACE,
        segmented_button_unselected_hover_color=_MUTED,
        text_color=_TXT1,
        text_color_disabled=_TXT1,
    )
    tabview.grid(row=2, column=0, sticky="nsew", pady=(0, 8))
    # On the tab line itself: the tab buttons are centred, so the left of that
    # strip is empty, and this is the one control every tab acts on.
    # x matches the header's padx so "Policy Name" starts on the same left
    # edge as "Your address" above it.
    policy_bar.place(in_=tabview, x=44, y=12)
    policy_bar.lift(tabview)   # a sibling placed over the tabview draws under it
    tabview.add("Dashboard")
    tabview.add("Guardians")
    tabview.add("Vault Keepers")
    tabview.add("Requester")
    tabview.add("Policies")
    # force white text on all tabs regardless of CTkTabview version
    try:
        tabview._segmented_button.configure(text_color=_TXT1, text_color_disabled=_TXT1)
    except Exception:
        pass

    # ═══════════════════════════════════════════════════════════════════════════
    # TAB 1 — Dashboard
    # ═══════════════════════════════════════════════════════════════════════════
    dash = tabview.tab("Dashboard")
    dash.grid_columnconfigure(0, weight=1)
    # The drop target sits in the last row and takes every spare pixel: the
    # settings above it are fixed-height, and this is what the window is for.
    dash.grid_rowconfigure(3, weight=1)

    # ── Row 0: Policy Name ────────────────────────────────────────────────────
    # The id this form produces, directly above the fields that produce it.
    S.file_id_var = tk.StringVar(value="policyId: waiting for Policy Name + Data Tag + Date")
    fileid_bar = ctk.CTkFrame(dash, fg_color=_SURFACE, corner_radius=8)
    fileid_bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))
    fileid_bar.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(
        fileid_bar, textvariable=S.file_id_var,
        font=("Consolas", 10), text_color=_TXT2, anchor="w",
    ).grid(row=0, column=0, sticky="ew", padx=14, pady=8)

    # ── Row 1: Select File + Data Tag + Date + AES ────────────────────────────
    file_card = ctk.CTkFrame(dash, corner_radius=12, fg_color=_SURFACE)
    file_card.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 4))
    # Column 0 held the drop target and is now empty, so it collapses; the
    # settings sit left and the spare width goes to the far end.
    file_card.grid_columnconfigure(0, weight=0)
    file_card.grid_columnconfigure(7, weight=1)

    S.selected_file_var = tk.StringVar(value="No file selected")

    # The drop target is the point of this window, so it is given room: a dashed
    # outline reads as "put something here" in a way a thin border does not, and
    # 2px is the thickest customtkinter will draw.
    # Parented to the tab, not to the settings card: it belongs at the bottom,
    # in the space the Network Results and Pieces panels used to take.
    file_drop = ctk.CTkFrame(
        dash, corner_radius=16,
        fg_color=_BASE, border_width=2, border_color=_MUTED,
    )
    file_drop.grid(row=3, column=0, sticky="nsew", padx=14, pady=(0, 14))
    file_drop.grid_columnconfigure(0, weight=1)
    file_drop.grid_rowconfigure(0, weight=1)
    file_drop.grid_rowconfigure(3, weight=1)
    file_drop.bind("<Button-1>", lambda _event: A.select_file(), add="+")

    select_btns = ctk.CTkFrame(file_drop, fg_color="transparent")
    select_btns.grid(row=1, column=0, pady=(2, 4))

    # Same corner as Upload File: three buttons on one screen doing the same
    # kind of job should not come in two shapes.
    select_btn = ctk.CTkButton(
        select_btns, text="📄  Select File", width=150, height=38,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 12), corner_radius=10,
        command=A.select_file,
    )
    select_btn.grid(row=0, column=0, padx=(0, 8))
    S.select_file_button = select_btn

    folder_btn = ctk.CTkButton(
        select_btns, text="📁  Select Folder", width=160, height=38,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 12), corner_radius=10,
        command=A.select_directory,
    )
    folder_btn.grid(row=0, column=1, padx=(8, 0))
    S.select_folder_button = folder_btn

    drop_hint_var = tk.StringVar(value="or drag and drop a file or folder here")
    drop_hint = ctk.CTkLabel(
        file_drop, textvariable=drop_hint_var,
        font=(_FONT, 10), text_color=_TXT2,
    )
    drop_hint.grid(row=2, column=0, padx=12, pady=(0, 2))

    selected_label = ctk.CTkLabel(
        file_drop, textvariable=S.selected_file_var,
        anchor="center", font=(_FONT, 10), text_color=_TXT1,
        wraplength=330,
    )
    selected_label.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 10))
    for _child in (drop_hint, selected_label):
        _child.bind("<Button-1>", lambda _event: A.select_file(), add="+")

    def _drag_enter():
        file_drop.configure(border_color=_ACCENT)

    def _drag_leave():
        file_drop.configure(border_color=_MUTED)

    def _drop(data):
        file_drop.configure(border_color=_MUTED)
        A.set_selected_file(_first_drop_file(data))

    dnd_enabled = _register_file_drop(
        file_drop,
        on_drop=_drop,
        on_enter=_drag_enter,
        on_leave=_drag_leave,
    )
    if not dnd_enabled:
        drop_hint_var.set("click here to select a file or folder")

    # 14 on the left, like every other row's first label. The cards all align at
    # the same x; what also has to align is the first thing inside each of them,
    # and these were landing at 50, 62 and 64.
    ctk.CTkLabel(file_card, text="Data Tag", font=(_FONT, 11), text_color=_TXT2).grid(
        row=0, column=1, padx=(14, 6), pady=10, sticky="e"
    )
    S.entry_device_id = ctk.CTkEntry(
        file_card, width=110,
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.entry_device_id.grid(row=0, column=2, padx=(0, 8), pady=10, sticky="w")
    # A fresh tag each time the window opens. The tag is part of the policy id,
    # so leaving the same one in the box invites two different uploads to claim
    # one id; it is still an ordinary text box, to be changed before uploading.
    S.entry_device_id.insert(0, A.new_data_tag())
    S.entry_device_id.bind("<KeyRelease>", lambda e: A.refresh_file_id_preview())

    # The date is part of the policy id, so it is shown on the button that sets
    # it rather than beside it: "Select Date" told you nothing about what was
    # selected, and a wrong date here produces a different policy id entirely.
    today_str = datetime.date.today().strftime("%Y-%m-%d")
    S.selected_datetime_var = tk.StringVar(value=today_str)
    S.date_button = ctk.CTkButton(
        file_card, textvariable=S.selected_datetime_var, width=124, height=28,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8, command=A.select_datetime,
    )
    S.date_button.grid(row=0, column=3, columnspan=2, padx=(0, 10), pady=10, sticky="w")

    S.chk_var = tk.BooleanVar(value=False)
    ctk.CTkSwitch(
        file_card, text="AES Encryption", variable=S.chk_var,
        font=(_FONT, 10), text_color=_TXT1,
        progress_color=_ACCENT, button_color=_TXT1, button_hover_color=_ACCENT_H,
        switch_height=16, switch_width=36,
        command=A.schedule_latest_upload_settings_save,
    ).grid(row=0, column=5, padx=(0, 12), pady=10)

    ctk.CTkLabel(file_card, text="Service Days", font=(_FONT, 10), text_color=_TXT2).grid(
        row=0, column=6, padx=(0, 6), pady=10, sticky="e"
    )
    S.entry_service_days = ctk.CTkEntry(
        file_card, width=52,
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.entry_service_days.grid(row=0, column=7, padx=(0, 14), pady=10, sticky="w")
    S.entry_service_days.insert(0, "30")
    S.entry_service_days.bind("<KeyRelease>", lambda e: (N.refresh_guardian_suitability(), A.schedule_latest_upload_settings_save()))

    # Policy ID info bar
    # Drop folder watcher
    drop_bar = ctk.CTkFrame(dash, fg_color=_SURFACE, corner_radius=8)
    drop_bar.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 4))
    drop_bar.grid_columnconfigure(2, weight=1)

    S.drop_folder_enabled_var = tk.BooleanVar(value=bool(getattr(C.config, "DROP_FOLDER_ENABLED", True)))
    S.drop_folder_delete_from_vk_var = tk.BooleanVar(value=bool(getattr(C.config, "DROP_FOLDER_DELETE_FROM_VK", False)))
    S.drop_folder_var = tk.StringVar(value=str(getattr(C.config, "DROP_FOLDER", Path(C.BASE_DIR) / "drop")))
    S.drop_folder_status_var = tk.StringVar(value="Drop folder: starting")

    # One switch, because the two were one idea: the folder either mirrors
    # what you store on the network or it does not. Two separate switches made
    # a half-state -- uploads watched, deletions ignored -- that nobody asked
    # for and that quietly left files on keepers after they were deleted here.
    ctk.CTkSwitch(
        drop_bar, text="Sync folder", variable=S.drop_folder_enabled_var,
        font=(_FONT, 10), text_color=_TXT1,
        progress_color=_ACCENT, button_color=_TXT1, button_hover_color=_ACCENT_H,
        switch_height=16, switch_width=36,
        command=A.sync_folder_toggled,
    ).grid(row=0, column=0, padx=(14, 16), pady=9, sticky="w")

    ctk.CTkLabel(
        drop_bar, textvariable=S.drop_folder_var,
        font=(_FONT, 10), text_color=_TXT2, anchor="w",
    ).grid(row=0, column=2, padx=(0, 8), pady=9, sticky="ew")

    _icon_btn(drop_bar, "📁", A.select_drop_folder, "Choose the folder to watch").grid(
        row=0, column=3, padx=(0, 4), pady=9
    )
    _icon_btn(drop_bar, "↗", A.open_drop_folder, "Open it in the file manager").grid(
        row=0, column=4, padx=(0, 12), pady=9
    )

    # Network Results and the Pieces Directory are windows of their own now, not
    # two panels taking the bottom half of a dashboard whose actual job is to
    # accept a file. They open from the tray, or from the two buttons in the
    # header. The log window starts with the recent history, so nothing is lost
    # by it not being on screen at all times.
    S.result_text = None
    S.pieces_listbox = None

    # ═══════════════════════════════════════════════════════════════════════════
    # TAB 2 — Guardians
    # ═══════════════════════════════════════════════════════════════════════════
    gtab = tabview.tab("Guardians")
    gtab.grid_columnconfigure(0, weight=1)
    gtab.grid_rowconfigure(1, weight=1)

    g_thresh_bar = ctk.CTkFrame(gtab, corner_radius=12, fg_color=_SURFACE)
    g_thresh_bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))
    g_thresh_bar.grid_columnconfigure(4, weight=1)

    ctk.CTkLabel(g_thresh_bar, text="Guardian Count (n)", font=(_FONT, 11), text_color=_TXT2).grid(
        row=0, column=0, padx=(14, 6), pady=8, sticky="e"
    )
    S.entry_guardian_n = ctk.CTkEntry(
        g_thresh_bar, width=55,
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.entry_guardian_n.grid(row=0, column=1, padx=(0, 14), pady=8, sticky="w")

    ctk.CTkLabel(g_thresh_bar, text="Threshold (t)", font=(_FONT, 11), text_color=_TXT2).grid(
        row=0, column=2, padx=(0, 6), pady=8, sticky="e"
    )
    S.entry_guardian_t = ctk.CTkEntry(
        g_thresh_bar, width=55,
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.entry_guardian_t.grid(row=0, column=3, padx=(0, 14), pady=8, sticky="w")

    g_btns = ctk.CTkFrame(g_thresh_bar, fg_color="transparent")
    g_btns.grid(row=0, column=4, sticky="ew", pady=6, padx=(16, 8))

    # Key buttons — right side
    ctk.CTkButton(g_btns, text="Same Key Refresh", width=128, height=28,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8, command=A.run_same_pk_refresh_request,
    ).pack(side="right")
    ctk.CTkButton(g_btns, text="Generate Key", width=112, height=28,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 10), corner_radius=8, command=A.run_keygen_request,
    ).pack(side="right", padx=(0, 4))

    # Guardian management buttons — left side
    if getattr(C,'DKG_ATTEMPT_PROTOCOL',0)==1:
        ctk.CTkButton(g_btns,text='Withdraw DKG credits',width=138,height=28,
            fg_color=_ACCENT_S,hover_color=_ACCENT_SH,text_color=_ACCENT,
            font=(_FONT,10),corner_radius=8,command=A.run_withdraw_dkg_credits,
        ).pack(side='right',padx=(0,4))
    ctk.CTkButton(g_btns, text="Add Selected", width=108, height=28,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 10), corner_radius=8, command=A.add_selected_guardians_to_policy,
    ).pack(side="left", padx=(0, 4))
    ctk.CTkButton(g_btns, text="Revoke Selected", width=118, height=28,
        fg_color="#4a0e0e", hover_color="#6b1414", text_color="#f87171",
        font=(_FONT, 10), corner_radius=8, command=A.remove_selected_guardians_from_policy,
    ).pack(side="left", padx=(0, 4))
    # No Clear Staged button: the ✕ above the table does it, and clearing the
    # staged list is the same act as clearing the selection it came from.

    ctk.CTkButton(g_btns, text="Create / Update Policy", width=165, height=28,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 10), corner_radius=8, command=A.create_or_update_file_policy,
    ).pack(side="left", padx=(0, 4))
    _btn_show_pol = ctk.CTkButton(g_btns, text="Show Policy", width=100, height=28,
        fg_color=_MUTED, hover_color=_MUTED_H, text_color=_TXT1,
        font=(_FONT, 10), corner_radius=8, command=A.show_current_file_policy,
    )
    _btn_show_pol.pack(side="left", padx=(0, 4))
    _add_tooltip(_btn_show_pol, "Show current policy and highlight its Guardians in the table")
    # One button: a policy is either on or off, and this says which it is now
    # and what pressing it does.
    S.policy_active_button = ctk.CTkButton(
        g_btns, text="Activate Policy", width=130, height=28,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8,
        command=A.toggle_current_file_policy_active,
    )
    S.policy_active_button.pack(side="left", padx=(0, 4))
    _btn_extend_service = ctk.CTkButton(g_btns, text="Extend Service", width=118, height=28,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8, command=A.extend_guardian_service,
    )
    _btn_extend_service.pack(side="left", padx=(0, 4))
    _add_tooltip(
        _btn_extend_service,
        "Buy more days on this policy's Guardian term. The start date stays put and "
        "every Guardian must agree before the end date moves; if one never answers, "
        "the parked payment comes back.",
    )
    S.entry_guardian_n.insert(0, "5")
    S.entry_guardian_n.bind("<KeyRelease>", lambda _e: A.schedule_latest_upload_settings_save())
    S.entry_guardian_t.insert(0, "3")
    S.entry_guardian_t.bind("<KeyRelease>", lambda _e: A.schedule_latest_upload_settings_save())

    # Guardian table
    guardian_table_frame = ctk.CTkFrame(gtab, fg_color=_SURFACE, corner_radius=8)
    guardian_table_frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 6))
    guardian_table_frame.grid_columnconfigure(0, weight=1)
    guardian_table_frame.grid_rowconfigure(1, weight=1)

    g_table_hdr = ctk.CTkFrame(guardian_table_frame, fg_color="transparent")
    g_table_hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=6, pady=(4, 0))
    g_table_hdr.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(
        g_table_hdr, text="Click column headers to sort",
        font=(_FONT, 9), text_color=_TXT2,
    ).grid(row=0, column=0, sticky="w")
    _icon_btn(g_table_hdr, "⟳", N.load_guardians, "Load Guardians", soft=True).grid(
        row=0, column=1, sticky="e", padx=(0, 4)
    )
    # Clears the staged list too, which also clears the selection -- they were
    # two buttons for one act.
    _icon_btn(
        g_table_hdr, "✕", A.clear_staged_guardians,
        "Clear the selection and the staged Guardians",
    ).grid(row=0, column=2, sticky="e")

    # container for treeview + overlay scrollbars
    _g_box = tk.Frame(guardian_table_frame, bg=_BASE, bd=0, highlightthickness=0)
    _g_box.grid(row=1, column=0, sticky="nsew", padx=6, pady=(2, 6))

    guardian_columns = (
        "status", "rep", "stake", "done", "fail", "total_proof_penalties",
        "dkg_material", "dkg_share", "pre", "daily_custody", "max_days",
        "suitable", "total_su", "cost", "source",
        "last_proof_at", "last_activity", "address",
    )
    S.guardians_listbox = ttk.Treeview(
        _g_box, columns=guardian_columns,
        show="headings", height=13, selectmode="extended",
        style="Guardian.Treeview",
    )
    S.guardians_listbox.place(relx=0, rely=0, relwidth=1.0, relheight=1.0)
    guardian_widths = {
        "status": 70, "rep": 55, "stake": 80, "done": 55, "fail": 50,
        "dkg_material": 90, "dkg_share": 90, "pre": 80,
        "daily_custody": 110, "max_days": 80, "suitable": 75,
        "total_su": 80, "cost": 145, "source": 55,
        "last_proof_at": 130, "total_proof_penalties": 115,
        "last_activity": 130, "address": 300,
    }
    _GUARDIAN_COL_HEADINGS = {
        "status": "Status", "rep": "Rep", "stake": "Stake FTU",
        "done": "Jobs", "fail": "Fail", "dkg_material": "DKG Mat SU",
        "dkg_share": "ShareKey SU", "pre": "PRE SU",
        "daily_custody": "Custody SU/day", "max_days": "Max Days",
        "suitable": "Suitable", "total_su": "Total SU",
        "cost": "Est. Cost", "source": "Price Src",
        "last_proof_at": "Last Proof", "total_proof_penalties": "Proof Penalties",
        "last_activity": "Last Activity",
        "address": "Guardian Address",
    }
    for col in guardian_columns:
        S.guardians_listbox.heading(
            col, text=_GUARDIAN_COL_HEADINGS[col],
            command=lambda c=col: N.sort_guardians_by_col(c),
        )
        S.guardians_listbox.column(
            col, width=guardian_widths[col], minwidth=guardian_widths[col],
            stretch=(col == "address"),
            anchor=("w" if col in {"address", "cost"} else "center"),
        )

    guardian_ys = ctk.CTkScrollbar(
        _g_box, orientation="vertical", command=S.guardians_listbox.yview,
        fg_color="transparent", button_color=_MUTED, button_hover_color=_ACCENT, width=12,
    )
    guardian_xs = ctk.CTkScrollbar(
        _g_box, orientation="horizontal", command=S.guardians_listbox.xview,
        fg_color="transparent", button_color=_MUTED, button_hover_color=_ACCENT, height=12,
    )
    S.guardians_listbox.configure(
        yscrollcommand=_make_autoscroll(guardian_ys, "vertical"),
        xscrollcommand=_make_autoscroll(guardian_xs, "horizontal"),
    )
    S.guardians_listbox.bind("<Button-1>", N.toggle_guardian_selection)
    S.guardians_listbox.tag_configure("unsuitable", foreground="#8899cc")
    S.guardians_listbox.tag_configure("stale_proof", foreground="#ff4444")
    S.guardians_listbox.tag_configure("dkg_complaint", foreground="#ff9900")
    S.guardians_listbox.tag_configure("pre_bad_partial", foreground="#ff6600")

    g_ctrl = ctk.CTkFrame(gtab, corner_radius=12, fg_color=_SURFACE)
    g_ctrl.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 14))

    g_row2 = ctk.CTkFrame(g_ctrl, fg_color="transparent")
    g_row2.grid(row=0, column=0, sticky="w", padx=10, pady=6)

    S.staged_g_status_var = tk.StringVar(value="Staged Guardians: none")
    ctk.CTkLabel(
        g_row2, textvariable=S.staged_g_status_var,
        font=(_FONT, 10), text_color=_ACCENT,
    ).pack(side="left", padx=(0, 24))

    S.policy_status_var = tk.StringVar(value="Policy: not loaded")
    ctk.CTkLabel(
        g_row2, textvariable=S.policy_status_var,
        font=(_FONT, 10), text_color=_TXT2,
    ).pack(side="left")

    # ═══════════════════════════════════════════════════════════════════════════
    # TAB 3 — Vault Keepers
    # ═══════════════════════════════════════════════════════════════════════════
    vtab = tabview.tab("Vault Keepers")
    vtab.grid_columnconfigure(0, weight=1)
    vtab.grid_rowconfigure(1, weight=1)  # table expands

    # ── Top control card ──────────────────────────────────────────────────────
    vk_top = ctk.CTkFrame(vtab, corner_radius=12, fg_color=_SURFACE)
    vk_top.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))

    # IDA config row
    ida_row = ctk.CTkFrame(vk_top, fg_color="transparent")
    ida_row.pack(fill="x", padx=10, pady=10)

    ctk.CTkLabel(ida_row, text="IDA Pieces (n)", font=(_FONT, 11), text_color=_TXT2).pack(side="left", padx=(0, 6))
    S.entry_n = ctk.CTkEntry(ida_row, width=55, fg_color=_BASE, text_color=_TXT1, border_color=_MUTED)
    S.entry_n.pack(side="left", padx=(0, 14))
    S.entry_n.insert(0, "6")

    ctk.CTkLabel(ida_row, text="Threshold (t)", font=(_FONT, 11), text_color=_TXT2).pack(side="left", padx=(0, 6))
    S.entry_t = ctk.CTkEntry(ida_row, width=55, fg_color=_BASE, text_color=_TXT1, border_color=_MUTED)
    S.entry_t.pack(side="left", padx=(0, 16))
    S.entry_t.insert(0, "4")

    # The sentence that stood here only restated the two boxes beside it, so
    # the buttons take the space instead and the card is one row shorter. The
    # variable stays: it is what the n/t bindings below write to.
    S.ida_info_var = tk.StringVar(value="")

    # bind manual edits to refresh the message
    S.entry_n.bind("<KeyRelease>", lambda e: (N.refresh_ida_info(), A.schedule_latest_upload_settings_save()))
    S.entry_t.bind("<KeyRelease>", lambda e: (N.refresh_ida_info(), A.schedule_latest_upload_settings_save()))

    # Clear Selection lives above the table it clears, beside Refresh.
    ctk.CTkButton(ida_row, text="Use for Upload", width=130, height=28,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 10), corner_radius=8, command=N.add_vks_to_policy,
    ).pack(side="left", padx=(0, 6))
    ctk.CTkButton(ida_row, text="Clear Upload VKs", width=130, height=28,
        fg_color="#4a0e0e", hover_color="#6b1414", text_color="#f87171",
        font=(_FONT, 10), corner_radius=8, command=N.clear_policy_vks,
    ).pack(side="left", padx=(0, 20))

    S.policy_vk_status_var = tk.StringVar(value="Upload VKs: none confirmed")
    ctk.CTkLabel(
        ida_row, textvariable=S.policy_vk_status_var,
        font=(_FONT, 10), text_color=_ACCENT,
    ).pack(side="left", padx=(0, 14))

    # ── Table / Map sub-tabview (row 1) ───────────────────────────────────────
    S.vk_tab_view = ctk.CTkTabview(
        vtab, fg_color=_SURFACE, corner_radius=8,
        segmented_button_fg_color=_BASE,
        segmented_button_selected_color=_ACCENT,
        segmented_button_selected_hover_color=_ACCENT_H,
        segmented_button_unselected_color=_MUTED,
        segmented_button_unselected_hover_color=_MUTED_H,
        command=N._on_vk_tab_change,
    )
    S.vk_tab_view.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
    S.vk_tab_view.add("Table")
    S.vk_tab_view.add("Map")

    # ── Table sub-tab ──────────────────────────────────────────────────────────
    _table_tab = S.vk_tab_view.tab("Table")
    _table_tab.grid_columnconfigure(0, weight=1)
    _table_tab.grid_rowconfigure(1, weight=1)

    vk_table_frame = ctk.CTkFrame(_table_tab, fg_color="transparent", corner_radius=0)
    vk_table_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
    vk_table_frame.grid_columnconfigure(0, weight=1)
    vk_table_frame.grid_rowconfigure(1, weight=1)

    vk_table_hdr = ctk.CTkFrame(vk_table_frame, fg_color="transparent")
    vk_table_hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=6, pady=(4, 0))
    vk_table_hdr.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(
        vk_table_hdr, text="Click column headers to sort",
        font=(_FONT, 9), text_color=_TXT2,
    ).grid(row=0, column=0, sticky="w")
    _icon_btn(vk_table_hdr, "⟳", N.load_vault_keepers, "Load Vault Keepers", soft=True).grid(
        row=0, column=1, sticky="e", padx=(0, 4)
    )
    # Above the table it clears, like the Guardians table's.
    _icon_btn(vk_table_hdr, "✕", N.clear_vault_keeper_selection, "Clear selection").grid(
        row=0, column=2, sticky="e"
    )

    # container for treeview + overlay scrollbars
    _vk_box = tk.Frame(vk_table_frame, bg=_BASE, bd=0, highlightthickness=0)
    _vk_box.grid(row=1, column=0, sticky="nsew", padx=6, pady=(2, 6))

    vk_columns = ("status", "eligible", "rep", "stake", "done", "fail", "fee", "fee_ftu", "max_days", "max_piece", "cap", "free", "served", "last_proof", "heartbeat", "ip", "location", "peer", "address")
    S.vault_keepers_listbox = ttk.Treeview(
        _vk_box, columns=vk_columns, show="headings",
        height=16, selectmode="extended", style="VK.Treeview",
    )
    S.vault_keepers_listbox.place(relx=0, rely=0, relwidth=1.0, relheight=1.0)
    vk_headings = {
        "status": "Status", "eligible": "Eligible", "rep": "Rep", "stake": "Stake FTU",
        "done": "Disputes", "fail": "Pen.Pts", "fee": "Fee SU/GB/d",
        "fee_ftu": "Est FTU/GB/d", "max_days": "Max Days", "max_piece": "Max Piece",
        "cap": "Capacity", "free": "Free",
        "served": "Served",
        "last_proof": "Last Proof", "heartbeat": "Heartbeat",
        "ip": "IP:Port", "location": "Location", "peer": "Peer ID", "address": "VK Address",
    }
    vk_widths = {
        "status": 68, "eligible": 70, "rep": 50, "stake": 80, "done": 65, "fail": 58,
        "fee": 65, "fee_ftu": 120, "max_days": 65, "max_piece": 90,
        "cap": 80, "free": 80,
        "served": 58,
        "last_proof": 110, "heartbeat": 110, "ip": 110, "location": 160, "peer": 110, "address": 320,
    }
    for col in vk_columns:
        S.vault_keepers_listbox.heading(col, text=vk_headings[col],
            command=lambda c=col: N.sort_vks_by_col(c))
        S.vault_keepers_listbox.column(
            col, width=vk_widths[col], minwidth=vk_widths[col],
            stretch=(col == "address"),
            anchor=("w" if col in {"address", "peer", "ip", "location"} else "center"),
        )
    S.vault_keepers_listbox.tag_configure("active", foreground=_TXT1)
    S.vault_keepers_listbox.tag_configure("off",    foreground=_TXT2)

    vk_ys = ctk.CTkScrollbar(
        _vk_box, orientation="vertical", command=S.vault_keepers_listbox.yview,
        fg_color="transparent", button_color=_MUTED, button_hover_color=_ACCENT, width=12,
    )
    vk_xs = ctk.CTkScrollbar(
        _vk_box, orientation="horizontal", command=S.vault_keepers_listbox.xview,
        fg_color="transparent", button_color=_MUTED, button_hover_color=_ACCENT, height=12,
    )
    S.vault_keepers_listbox.configure(
        yscrollcommand=_make_autoscroll(vk_ys, "vertical"),
        xscrollcommand=_make_autoscroll(vk_xs, "horizontal"),
    )
    S.vault_keepers_listbox.bind("<Button-1>", N.toggle_vault_keeper_selection)

    # ── Map sub-tab ────────────────────────────────────────────────────────────
    _map_tab = S.vk_tab_view.tab("Map")
    _map_tab.grid_columnconfigure(0, weight=1)
    _map_tab.grid_rowconfigure(1, weight=1)

    # Navigation / info bar
    _map_nav = ctk.CTkFrame(_map_tab, fg_color="transparent")
    _map_nav.grid(row=0, column=0, sticky="ew", padx=6, pady=(4, 2))
    _map_nav.grid_columnconfigure(2, weight=1)

    S.vk_map_back_btn = ctk.CTkButton(
        _map_nav, text="← Back", state="disabled", width=90, height=26,
        fg_color=_MUTED, hover_color=_MUTED_H, text_color=_TXT1,
        font=(_FONT, 10), corner_radius=8, command=N.vk_map_go_back,
    )
    S.vk_map_back_btn.grid(row=0, column=0, padx=(0, 6))

    ctk.CTkButton(
        _map_nav, text="⟳ Refresh", width=80, height=26,
        fg_color=_MUTED, hover_color=_MUTED_H, text_color=_TXT1,
        font=(_FONT, 10), corner_radius=8, command=N.refresh_vk_map,
    ).grid(row=0, column=1, padx=(0, 10))

    S.vk_map_info_var = tk.StringVar(value="")
    ctk.CTkLabel(
        _map_nav, textvariable=S.vk_map_info_var,
        font=(_FONT, 10), text_color=_ACCENT, anchor="w",
    ).grid(row=0, column=2, sticky="ew")

    S.vk_map_local_var = tk.StringVar(value="")
    ctk.CTkLabel(
        _map_nav, textvariable=S.vk_map_local_var,
        font=(_FONT, 10), text_color=_TXT2,
    ).grid(row=0, column=3, padx=(10, 0))

    # Map widget (inside a plain tk.Frame — TkinterMapView needs standard tk parent)
    _map_frame = tk.Frame(_map_tab, bg=_BASE, bd=0, highlightthickness=0)
    _map_frame.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
    _map_frame.grid_columnconfigure(0, weight=1)
    _map_frame.grid_rowconfigure(0, weight=1)

    try:
        import tkintermapview
        from . import do_map_tiles
        if do_map_tiles.prefer_ipv4_if_ipv6_is_dead():
            L.log("[map] IPv6 does not connect here; fetching map tiles over IPv4")
        S.vk_map_widget = tkintermapview.TkinterMapView(
            _map_frame, width=800, height=440, corner_radius=0,
        )
        S.vk_map_widget.grid(row=0, column=0, sticky="nsew")
        # OpenStreetMap, which serves tiles to anyone without an account. The
        # label-free CartoDB basemap this used to draw now answers every
        # request with an "API KEY REQUIRED" watermark, so the map that looked
        # tidier is the map nobody can see. A user with their own provider can
        # still name one in config.
        tile_server = str(
            getattr(C.config, "MAP_TILE_SERVER", "") or ""
        ).strip() or "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
        try:
            max_zoom = int(getattr(C.config, "MAP_MAX_ZOOM", 19) or 19)
        except (TypeError, ValueError):
            max_zoom = 19
        S.vk_map_widget.set_tile_server(tile_server, max_zoom=max_zoom)
        S.vk_map_widget.set_position(20, 10)
        S.vk_map_widget.set_zoom(2)
    except ImportError:
        # The map package is optional and is the one dependency a user can be
        # missing while every other tab works, so say what to run rather than
        # showing them a bare ModuleNotFoundError.
        import sys
        tk.Label(
            _map_frame,
            text=(
                "The map package is not installed, so the keeper map cannot be "
                "drawn.\nEverything else in the app works without it.\n\n"
                "To install it, run:\n"
                f"    {sys.executable} -m pip install tkintermapview"
            ),
            bg=_BASE, fg=_TXT2, font=(_FONT, 11), justify="left",
        ).grid(row=0, column=0)
        S.vk_map_widget = None
    except Exception as _map_err:
        tk.Label(
            _map_frame,
            text=f"Map unavailable: {_map_err}",
            bg=_BASE, fg=_TXT2, font=(_FONT, 11),
        ).grid(row=0, column=0)
        S.vk_map_widget = None

    # ═══════════════════════════════════════════════════════════════════════════
    # TAB 4 — Requester
    # ═══════════════════════════════════════════════════════════════════════════
    rtab = tabview.tab("Requester")
    rtab.grid_columnconfigure(0, weight=1)
    rtab.grid_rowconfigure(1, weight=1)

    req_card = ctk.CTkFrame(rtab, corner_radius=12, fg_color=_SURFACE)
    req_card.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 6))

    _section_label(req_card, "Requester Address Management").grid(
        row=0, column=0, columnspan=6, sticky="w", padx=14, pady=(10, 4)
    )
    ctk.CTkLabel(
        req_card,
        text="Select a policy in the Dashboard tab first. Requesters below are specific to that policy.",
        font=(_FONT, 10), text_color=_TXT2,
    ).grid(row=1, column=0, columnspan=6, sticky="w", padx=14, pady=(0, 8))

    ctk.CTkLabel(req_card, text="Name", font=(_FONT, 11), text_color=_TXT2).grid(
        row=2, column=0, padx=(14, 6), pady=10, sticky="e"
    )
    S.entry_req_name = ctk.CTkEntry(
        req_card, width=150, placeholder_text="optional",
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.entry_req_name.grid(row=2, column=1, padx=(0, 14), pady=10, sticky="w")

    ctk.CTkLabel(req_card, text="Address", font=(_FONT, 11), text_color=_TXT2).grid(
        row=2, column=2, padx=(0, 6), pady=10, sticky="e"
    )
    S.entry_req_address = ctk.CTkEntry(
        req_card, width=380,
        fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.entry_req_address.grid(row=2, column=3, padx=(0, 10), pady=10, sticky="w")
    S.entry_req_address.insert(0, A.default_requester_address())

    ctk.CTkButton(req_card, text="Add Requester", width=130, height=32,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 11), corner_radius=10, command=A.add_requester_to_file,
    ).grid(row=2, column=4, padx=(0, 8), pady=10)
    ctk.CTkButton(req_card, text="Revoke Requester", width=145, height=32,
        fg_color="#4a0e0e", hover_color="#6b1414", text_color="#f87171",
        font=(_FONT, 11), corner_radius=10, command=A.remove_requester_from_file,
    ).grid(row=2, column=5, padx=(0, 14), pady=10)

    req_book_frame = ctk.CTkFrame(rtab, corner_radius=12, fg_color=_SURFACE)
    req_book_frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
    req_book_frame.grid_columnconfigure(0, weight=1)
    req_book_frame.grid_rowconfigure(1, weight=1)

    book_header = ctk.CTkFrame(req_book_frame, fg_color="transparent")
    book_header.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))
    book_header.grid_columnconfigure(0, weight=1)

    _section_label(book_header, "Policy Requesters").grid(row=0, column=0, sticky="w")
    _icon_btn(book_header, "⟳", A.sync_policy_requesters,
              "Sync from chain — verify on-chain state and update local record", soft=True,
    ).grid(row=0, column=1, sticky="e", padx=(8, 0))
    ctk.CTkLabel(
        book_header,
        text="Select one or more rows and click Revoke Requester to remove them on-chain.",
        font=(_FONT, 10), text_color=_TXT2,
    ).grid(row=1, column=0, columnspan=2, sticky="w")

    S.req_book_tree = ttk.Treeview(
        req_book_frame, columns=("name", "address"),
        show="headings", style="ReqBook.Treeview", selectmode="extended",
    )
    S.req_book_tree.heading("name",    text="Name",           command=lambda: N.sort_req_book_by_col("name"))
    S.req_book_tree.heading("address", text="Wallet Address", command=lambda: N.sort_req_book_by_col("address"))
    S.req_book_tree.column("name",    width=200, minwidth=120, anchor="w")
    S.req_book_tree.column("address", width=480, minwidth=200, stretch=True, anchor="w")

    req_book_ys = ctk.CTkScrollbar(
        req_book_frame, orientation="vertical", command=S.req_book_tree.yview,
        fg_color=_SURFACE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    S.req_book_tree.configure(yscrollcommand=req_book_ys.set)
    S.req_book_tree.grid(row=1, column=0, sticky="nsew", padx=(14, 0), pady=(0, 14))
    req_book_ys.grid(row=1, column=1, sticky="ns", pady=(0, 14), padx=(0, 14))
    S.req_book_tree.bind("<<TreeviewSelect>>", N.req_book_row_selected)

    # ═══════════════════════════════════════════════════════════════════════════
    # TAB 5 — Policies
    # ═══════════════════════════════════════════════════════════════════════════
    ptab = tabview.tab("Policies")
    # Two columns: the three tables stack on the left, where they need the
    # width, and the policy text stands in a column of its own on the right,
    # full height, instead of a two-line box squeezed between two tables.
    ptab.grid_columnconfigure(0, weight=3)
    ptab.grid_columnconfigure(1, weight=1, minsize=330)
    ptab.grid_rowconfigure(1, weight=2, minsize=120)
    ptab.grid_rowconfigure(2, weight=2, minsize=160)
    # The pieces table is what the delete buttons act on, so it gets a floor it
    # cannot be squeezed below.
    ptab.grid_rowconfigure(3, weight=3, minsize=200)

    pol_header = ctk.CTkFrame(ptab, fg_color="transparent")
    pol_header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
    pol_header.grid_columnconfigure(1, weight=1)

    _section_label(pol_header, "Policy Browser").grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(
        pol_header,
        text="Policies are saved locally when you Create/Update a policy or complete a file upload.",
        font=(_FONT, 10), text_color=_TXT2,
    ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))

    # One refresh for the whole tab: policies, and the pieces below them.
    _icon_btn(
        pol_header, "⟳", A.refresh_policies_tab,
        "Reload the policies and the stored pieces", height=28, soft=True,
    ).grid(row=0, column=2, sticky="e", padx=(0, 6))
    ctk.CTkButton(
        pol_header, text="⛓  Sync from Chain", width=150, height=28,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 10), corner_radius=8, command=A.run_sync_policies_from_chain,
    ).grid(row=0, column=3, sticky="e")

    pol_tree_frame = ctk.CTkFrame(ptab, fg_color=_SURFACE, corner_radius=8)
    pol_tree_frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 4))
    pol_tree_frame.grid_columnconfigure(0, weight=1)
    pol_tree_frame.grid_rowconfigure(0, weight=1)

    pol_columns = ("name", "fileid", "gs", "files", "created")
    S.policies_tree = ttk.Treeview(
        pol_tree_frame, columns=pol_columns, show="headings",
        height=4, selectmode="browse", style="Pol.Treeview",
    )
    pol_headings = {
        "name": "Policy Name", "fileid": "Policy ID",
        "gs": "Guardians", "files": "Files", "created": "Created",
    }
    pol_widths = {"name": 160, "fileid": 200, "gs": 80, "files": 70, "created": 110}
    for col in pol_columns:
        S.policies_tree.heading(col, text=pol_headings[col],
            command=lambda c=col: N.sort_policies_by_col(c))
        S.policies_tree.column(
            col, width=pol_widths[col], minwidth=pol_widths[col],
            stretch=(col == "fileid"),
            anchor=("w" if col in {"name", "fileid"} else "center"),
        )

    pol_ys = ctk.CTkScrollbar(
        pol_tree_frame, orientation="vertical", command=S.policies_tree.yview,
        fg_color=_SURFACE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    S.policies_tree.configure(yscrollcommand=pol_ys.set)
    S.policies_tree.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=6)
    pol_ys.grid(row=0, column=1, sticky="ns", pady=6, padx=(0, 6))
    S.policies_tree.bind("<<TreeviewSelect>>", A.show_policy_detail)

    # ── Policy Detail — the right-hand column, full height ───────────────────
    detail_col = ctk.CTkFrame(ptab, fg_color=_SURFACE, corner_radius=8)
    detail_col.grid(row=0, column=1, rowspan=4, sticky="nsew", padx=(0, 14),
                    pady=(12, 14))
    detail_col.grid_columnconfigure(0, weight=1)
    detail_col.grid_rowconfigure(1, weight=1)
    _section_label(detail_col, "Policy Detail").grid(
        row=0, column=0, sticky="w", padx=14, pady=(8, 2)
    )
    S.policy_detail_text = ctk.CTkTextbox(
        detail_col, corner_radius=8, font=("Consolas", 10),
        text_color=_TXT1, fg_color=_BASE,
        border_width=1, border_color=_MUTED,
        state="disabled",
    )
    S.policy_detail_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 12))

    pol_detail_frame = ctk.CTkFrame(ptab, fg_color=_SURFACE, corner_radius=8)
    pol_detail_frame.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))
    pol_detail_frame.grid_columnconfigure(0, weight=1)

    # A policy holds several files, so the files inside it are a list you can
    # select from, not a paragraph you can only read. Choosing one here is what
    # narrows the pieces table below, and what the file-level delete acts on.
    pol_detail_frame.grid_rowconfigure(0, weight=0)
    pol_detail_frame.grid_rowconfigure(1, weight=1, minsize=110)

    pf_hdr = ctk.CTkFrame(pol_detail_frame, fg_color="transparent")
    pf_hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(8, 2))
    pf_hdr.grid_columnconfigure(0, weight=1)
    _section_label(pf_hdr, "Files in this policy").grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(
        pf_hdr,
        text="Select a file to see only its pieces below.",
        font=(_FONT, 9), text_color=_TXT2,
    ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(1, 0))
    # Recovery sits beside the file list because that is where its absence is
    # noticed: a policy from the chain with no files under it.
    _btn_recover = ctk.CTkButton(
        pf_hdr, text="Recover from network", width=165, height=26,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8,
        command=A.recover_selected_policy_file,
    )
    _btn_recover.grid(row=0, column=1, sticky="e", padx=(0, 6))
    _add_tooltip(
        _btn_recover,
        "Rebuild this policy's pieces and keepers from the network, after a\n"
        "reinstall or on a new computer. Asks the guardians for your own\n"
        "file's key, which costs the usual access fee.",
    )
    ctk.CTkButton(
        pf_hdr, text="Delete this file from all VKs", width=200, height=26,
        fg_color="#4a0e0e", hover_color="#6b1414", text_color="#f87171",
        font=(_FONT, 10), corner_radius=8,
        command=A.delete_selected_file_from_vks,
    ).grid(row=0, column=2, sticky="e")

    pf_tree_frame = ctk.CTkFrame(pol_detail_frame, fg_color="transparent")
    pf_tree_frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
    pf_tree_frame.grid_columnconfigure(0, weight=1)
    pf_tree_frame.grid_rowconfigure(0, weight=1)
    pf_cols = ("tag", "date", "uploaded", "pieces", "keepers")
    S.policy_files_tree = ttk.Treeview(
        pf_tree_frame, columns=pf_cols, show="headings",
        height=3, selectmode="browse", style="Pol.Treeview",
    )
    pf_headings = {
        "tag": "Data Tag", "date": "Date", "uploaded": "Uploaded",
        "pieces": "Pieces", "keepers": "Keepers",
    }
    pf_widths = {"tag": 200, "date": 110, "uploaded": 150, "pieces": 70, "keepers": 80}
    for col in pf_cols:
        S.policy_files_tree.heading(col, text=pf_headings[col])
        S.policy_files_tree.column(
            col, width=pf_widths[col], minwidth=pf_widths[col],
            stretch=(col == "tag"),
            anchor=("center" if col in {"pieces", "keepers"} else "w"),
        )
    pf_ys = ctk.CTkScrollbar(
        pf_tree_frame, orientation="vertical", command=S.policy_files_tree.yview,
        fg_color=_SURFACE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    S.policy_files_tree.configure(yscrollcommand=pf_ys.set)
    S.policy_files_tree.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=6)
    pf_ys.grid(row=0, column=1, sticky="ns", pady=6, padx=(0, 6))
    S.policy_files_tree.bind("<<TreeviewSelect>>", A.on_policy_file_selected)

    # ── Stored VK Pieces (row 3 of Policies tab) ─────────────────────────────
    sp_frame = ctk.CTkFrame(ptab, fg_color=_SURFACE, corner_radius=8)
    sp_frame.grid(row=3, column=0, sticky="nsew", padx=14, pady=(0, 14))
    sp_frame.grid_columnconfigure(0, weight=1)
    sp_frame.grid_rowconfigure(1, weight=1)

    sp_hdr = ctk.CTkFrame(sp_frame, fg_color="transparent")
    sp_hdr.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 2))
    sp_hdr.grid_columnconfigure(0, weight=1)
    _section_label(sp_hdr, "Stored VK Pieces").grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(
        sp_hdr,
        text="Pick a policy, then a file in it, to see that file's pieces here.",
        font=(_FONT, 9), text_color=_TXT2,
    ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(1, 0))
    # No reload button here: the one at the top of the tab reloads this table
    # too, and two refreshes on one screen only raise the question of what is
    # different about them.
    ctk.CTkButton(
        sp_hdr, text="Delete this piece from VK", width=175, height=26,
        fg_color="#4a0e0e", hover_color="#6b1414", text_color="#f87171",
        font=(_FONT, 10), corner_radius=8,
        command=A.delete_vk_piece_selected,
    ).grid(row=0, column=2, sticky="e", padx=(0, 4))
    _btn_dispute = ctk.CTkButton(
        sp_hdr, text="Dispute Deletion Failure", width=170, height=26,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8,
        command=A.dispute_deletion_failure_selected,
    )
    _btn_dispute.grid(row=0, column=3, sticky="e")
    _add_tooltip(
        _btn_dispute,
        "With a piece selected, disputes that piece. With only a file "
        "selected, disputes every piece of it you asked to delete and the "
        "keeper never confirmed.",
    )

    sp_tree_frame = ctk.CTkFrame(sp_frame, fg_color="transparent")
    sp_tree_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 10))
    sp_tree_frame.grid_columnconfigure(0, weight=1)
    sp_tree_frame.grid_rowconfigure(0, weight=1)

    sp_cols = ("idx", "piece_root", "vk_peer", "service_end", "commitment_hash")
    S.stored_pieces_tree = ttk.Treeview(
        sp_tree_frame, columns=sp_cols, show="headings",
        height=6, selectmode="browse", style="Pol.Treeview",
    )
    sp_headings = {
        "idx": "#", "piece_root": "Piece Root",
        "vk_peer": "VK Peer", "service_end": "Service End",
        "commitment_hash": "Commitment Hash",
    }
    sp_widths = {"idx": 34, "piece_root": 160, "vk_peer": 160, "service_end": 100, "commitment_hash": 160}
    for col in sp_cols:
        S.stored_pieces_tree.heading(col, text=sp_headings[col])
        S.stored_pieces_tree.column(
            col, width=sp_widths[col], minwidth=sp_widths[col],
            stretch=(col == "commitment_hash"),
            anchor=("center" if col == "idx" else "w"),
        )
    S.stored_pieces_tree.grid(row=0, column=0, sticky="nsew")
    sp_ys = ctk.CTkScrollbar(
        sp_tree_frame, orientation="vertical", command=S.stored_pieces_tree.yview,
        fg_color=_SURFACE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    sp_ys.grid(row=0, column=1, sticky="ns")
    S.stored_pieces_tree.configure(yscrollcommand=sp_ys.set)

    # ── Status bar ──────────────────────────────────────────────────────────────
    sb = ctk.CTkFrame(main, fg_color="transparent")
    sb.grid(row=3, column=0, sticky="ew", padx=44, pady=(0, 16))
    # The side columns share the spare width equally, so the bar sits in the
    # middle of the window and stays there. Letting the status pill size its
    # own column made the bar slide left and right as the wording changed.
    sb.grid_columnconfigure(0, weight=1, uniform="statusbar")
    sb.grid_columnconfigure(2, weight=1, uniform="statusbar", minsize=170)

    ctk.CTkLabel(sb, text="Status", font=(_FONT, 9), text_color=_TXT2).grid(
        row=0, column=0, sticky="w"
    )
    S.status_var = tk.StringVar(value="Ready")
    S.status_label = ctk.CTkLabel(
        sb, textvariable=S.status_var,
        font=(_FONT, 9), text_color="#1F2641",
        fg_color=_ACCENT, corner_radius=999,
        padx=10, pady=3,
    )
    S.status_label.grid(row=0, column=2, sticky="e")

    # One bar for whatever was asked for -- an upload, a delete, anything long
    # enough to worry about. Hidden until something is running, because a bar
    # at zero with nothing happening reads as a task that has stalled.
    S.progress_var = tk.StringVar(value="")
    sb.grid_columnconfigure(1, weight=0)
    S.progress_box = ctk.CTkFrame(sb, fg_color="transparent")
    S.progress_box.grid(row=0, column=1, padx=10)
    S.progress_bar = ctk.CTkProgressBar(
        S.progress_box, width=220, height=10, corner_radius=999,
        fg_color=_MUTED, progress_color=_ACCENT,
    )
    S.progress_bar.set(0)
    S.progress_bar.pack(side="right")
    ctk.CTkLabel(
        S.progress_box, textvariable=S.progress_var,
        font=(_FONT, 9), text_color=_TXT2,
    ).pack(side="right", padx=(0, 8))
    S.progress_box.grid_remove()   # shown by do_progress once work starts

    # Initial load — everything here reads local files and finishes at once.
    A.restore_latest_upload_settings()
    A.refresh_file_id_preview()
    A.refresh_pieces_list()
    A.init_pk_from_file()
    A.load_stored_pieces_list()
    N.load_guardians()
    A.load_policies_browser()
    N.load_policy_requesters_ui()
    # The keepers are asked over the network, which takes seconds, so they are
    # fetched after the window is on screen rather than before it.
    _start_network_warmup()
    A.repair_recovered_pieces_once()
    A.retry_unsent_admission_disputes_once()
    VM.start_storage_verification_reconciler()
    A.start_pending_dkg_reconciler()
    A.start_drop_folder_watcher()
    # Last, and after the window exists: it may ask a question, and a dialog
    # raised before there is a window behind it has nothing to sit on.
    S.root.after(800, A.offer_unfinished_upload_resume)
    tray_started = False if __import__('os').environ.get('FILETRUST_CONTAINER') == '1' else T.start_tray_icon()
    if tray_started:
        S.root.protocol("WM_DELETE_WINDOW", T.hide_window_to_tray)
    else:
        S.root.protocol("WM_DELETE_WINDOW", A.exit_app)

    from .ft_update_ui import attach
    from . import do_progress
    attach(S.root, Path(__file__).resolve().parents[1], busy=do_progress.is_running)
    from .ft_update_bootstrap import ready
    ready(Path(__file__).resolve().parents[1])
    if __import__('os').environ.get('FILETRUST_CONTAINER') == '1':
        from .ft_desktop_lifecycle import install
        install(S.root, do_progress.is_running, A.exit_app)
    S.root.mainloop()


def _set_upload_controls_enabled(enabled: bool) -> None:
    """Upload needs keepers, so it waits for them; the rest of the window does not."""
    for widget in (S.upload_button, S.select_file_button, S.select_folder_button):
        if widget is None:
            continue
        try:
            widget.configure(state="normal" if enabled else "disabled")
        except Exception:
            pass


def _start_network_warmup() -> None:
    """Load the keepers without holding the window shut.

    Every keeper is asked over the network for its live capacity, and the
    guardians are confirmed against the chain -- together about ten seconds,
    and all of it used to run before the window was drawn, so the app looked
    frozen before it had shown anything. The fetch happens on a worker; the
    tables, which belong to the UI thread, are filled when it lands.
    """
    L.set_status("Loading the keeper network...", "running")
    _set_upload_controls_enabled(False)

    def finish(rows, error) -> None:
        if error:
            L.log(f"[startup] could not load the keepers: {error}")
            L.set_status("Could not load the keepers — use Refresh", "error")
        else:
            N.load_vault_keepers(rows=rows)
            if S.auto_select_var is not None and S.auto_select_var.get():
                A.apply_auto_selection_from_latest(show_errors=False)
            L.set_status("Ready", "ready")
        _set_upload_controls_enabled(True)

    def work() -> None:
        rows, error = None, None
        try:
            rows = N.fetch_vk_rows()
        except Exception as exc:
            error = exc
        if S.root is not None:
            S.root.after(0, lambda: finish(rows, error))

    threading.Thread(target=work, daemon=True, name="startup-keepers").start()
