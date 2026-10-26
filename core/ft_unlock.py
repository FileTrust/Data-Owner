# ft_unlock.py — ask for the password (and the code) before the app opens.
#
# Called by DO.py / REQ.py as the very first thing, before any module that
# needs an account is imported. That order is the whole design: the config
# module derives the signing account at import time, so the key has to be in
# memory before it runs. The unlocked key is left in ft_keyvault for the config
# module to pick up, rather than in an environment variable every child process
# would inherit.
#
# An install with no vault file is the normal case for everyone who has not
# chosen a password: unlock_app_key() returns success immediately and nothing
# about the start-up changes.
#
# The prompt is a small window when there is a display, and a terminal prompt
# when there is not -- the same app runs over SSH on a headless box, and
# "cannot open display" is a poor reason to refuse someone their own key.

from __future__ import annotations

import os
import sys

from . import ft_keyvault as V

ATTEMPTS = 3
_FONT = "Catamaran"
_BASE = "#232840"
_SURFACE = "#2A3355"
_ACCENT = "#FFD700"
_TXT1 = "#E6ECFF"
_TXT2 = "#8899cc"
_MUTED = "#3E497A"


def _have_display() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _ask_in_terminal(prompt: str, *, mask: bool) -> str | None:
    import getpass

    try:
        if mask:
            return getpass.getpass(prompt)
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return None


def _ask_in_window(title: str, heading: str, note: str, *, mask: bool,
                   error: str = "") -> str | None:
    """One small dialog. Returns the text, or None if it was closed."""
    import tkinter as tk

    answer: dict[str, str | None] = {"value": None}
    root = tk.Tk()
    root.title(title)
    root.configure(bg=_BASE)
    root.resizable(False, False)

    frame = tk.Frame(root, bg=_SURFACE, padx=22, pady=18)
    frame.pack(padx=14, pady=14)
    tk.Label(frame, text=heading, bg=_SURFACE, fg=_TXT1,
             font=(_FONT, 13)).pack(anchor="w")
    if note:
        tk.Label(frame, text=note, bg=_SURFACE, fg=_TXT2, font=(_FONT, 10),
                 wraplength=360, justify="left").pack(anchor="w", pady=(4, 0))
    entry = tk.Entry(frame, show="*" if mask else "", width=32, bg=_BASE, fg=_TXT1,
                     insertbackground=_ACCENT, relief="flat", font=(_FONT, 12))
    entry.pack(anchor="w", pady=(12, 4), ipady=6, fill="x")
    entry.focus_force()
    message = tk.Label(frame, text=error, bg=_SURFACE, fg="#FF8080",
                       font=(_FONT, 10), wraplength=360, justify="left")
    message.pack(anchor="w")

    def accept(_event=None) -> None:
        answer["value"] = entry.get()
        root.destroy()

    def cancel(_event=None) -> None:
        answer["value"] = None
        root.destroy()

    buttons = tk.Frame(frame, bg=_SURFACE)
    buttons.pack(anchor="e", pady=(12, 0))
    tk.Button(buttons, text="Quit", command=cancel, bg=_MUTED, fg=_TXT1,
              activebackground=_MUTED, relief="flat", font=(_FONT, 10),
              padx=12, pady=4).pack(side="left", padx=(0, 8))
    tk.Button(buttons, text="Unlock", command=accept, bg=_ACCENT, fg=_BASE,
              activebackground=_ACCENT, relief="flat", font=(_FONT, 10),
              padx=16, pady=4).pack(side="left")

    entry.bind("<Return>", accept)
    root.bind("<Escape>", cancel)
    root.protocol("WM_DELETE_WINDOW", cancel)
    root.eval("tk::PlaceWindow . center")
    root.mainloop()
    return answer["value"]


def _ask(title: str, heading: str, note: str, terminal_prompt: str, *,
         mask: bool, error: str = "") -> str | None:
    if _have_display():
        try:
            return _ask_in_window(title, heading, note, mask=mask, error=error)
        except Exception:
            pass  # a display that exists but will not serve us: fall through
    if error:
        print(f"  {error}", file=sys.stderr)
    return _ask_in_terminal(terminal_prompt, mask=mask)


def unlock_app_key(base_dir, app_title: str) -> tuple[bool, str]:
    """Put the account key in memory. Returns (ready, why not).

    Three ways to succeed: there is no vault (nothing to unlock), the password
    is in the environment (scripts and headless runs), or the user types it.
    """
    path = V.vault_path(base_dir)
    if not V.exists(path):
        return True, ""

    # An environment password skips both prompts on purpose: the caller already
    # proved they have the password, and a second factor cannot be typed by a
    # cron job. A user who wants the code enforced simply does not set it.
    try:
        from_env = V.key_from_environment(path)
    except V.VaultError as exc:
        return False, str(exc)
    if from_env:
        V.remember_key(from_env)
        return True, ""

    # The keyring, which the desktop unlocked at login. This is the default
    # setup, so the usual start-up asks for nothing at all. A keyring that has
    # been reset, or a vault carried to another machine, simply falls through
    # to the prompt: the password printed at setup still opens it.
    stored = V.password_from_keyring(path)
    payload = None
    if stored:
        try:
            payload = V.unlock(path, stored)
        except V.BadPassword:
            payload = None   # stale entry; ask instead of giving up
        except V.VaultError as exc:
            return False, str(exc)
    if payload is not None:
        return _finish(path, payload, app_title)

    address = V.address_in(path)
    note = f"Account {address[:10]}…{address[-4:]}" if address else ""
    error = ""
    payload = None
    for attempt in range(ATTEMPTS):
        password = _ask(
            f"{app_title} — unlock",
            "Password",
            note or "This app's key is protected by a password.",
            "Password: ", mask=True, error=error,
        )
        if password is None:
            return False, "cancelled"
        try:
            payload = V.unlock(path, password)
            break
        except V.BadPassword as exc:
            left = ATTEMPTS - attempt - 1
            if not left:
                return False, str(exc)
            error = f"{exc}. {left} attempt(s) left."
        except V.VaultError as exc:
            return False, str(exc)

    if payload is None:  # pragma: no cover - the loop always sets or returns
        return False, "could not open the key vault"

    return _finish(path, payload, app_title)


def _finish(path, payload: dict, app_title: str) -> tuple[bool, str]:
    """Ask for the authenticator code if there is one, then hand the key over.

    Reached from both routes -- keyring and typed password -- because the
    second factor is a gate on the app starting, and a keyring that answers
    for the password must not also answer for the code.
    """
    secret = payload.get("totp_secret")
    error = ""
    if secret:
        for attempt in range(ATTEMPTS):
            code = _ask(
                f"{app_title} — two-factor",
                "Authenticator code",
                "Type the 6-digit code from your authenticator app.",
                "Two-factor code: ", mask=False, error=error,
            )
            if code is None:
                return False, "cancelled"
            if V.totp_matches(secret, code):
                break
            left = ATTEMPTS - attempt - 1
            if not left:
                return False, "the two-factor code did not match"
            error = f"That code did not match. {left} attempt(s) left."

    V.remember_key(payload["private_key"])
    return True, ""
