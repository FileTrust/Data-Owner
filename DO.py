#!/usr/bin/env python3
import sys
import os

if __name__ == "__main__":
    from pathlib import Path
    from ft_update_bootstrap import enter
    enter(Path(__file__).resolve().parent)

# Ensure App/DO/ is on sys.path so 'core' is importable as a package.
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)


def _restart_in_app_environment() -> None:
    """Start over using the interpreter install.sh prepared, if we are not it.

    `python3 DO.py` is the obvious thing to type, and it is wrong: the system
    interpreter has none of the packages install.sh installed. What the user
    sees is not a clean failure but a window with pieces missing -- the keeper
    map absent, for instance -- and no reason given. So if the environment
    install.sh builds is sitting right next to this file, hand over to it.
    """
    if os.environ.get("FILETRUST_DO_RESTARTED") == "1":
        return  # already tried once; never loop
    venv = os.path.join(_this_dir, ".venv")
    if os.path.realpath(sys.prefix) == os.path.realpath(venv):
        return  # this *is* the app environment
    for rel in (("bin", "python"), ("Scripts", "python.exe")):
        candidate = os.path.join(venv, *rel)
        if os.access(candidate, os.X_OK):
            break
    else:
        return  # not installed yet; run with whatever we have
    os.environ["FILETRUST_DO_RESTARTED"] = "1"
    print("Starting with the app's own Python environment.", file=sys.stderr)
    try:
        os.execv(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]])
    except OSError as exc:
        # A damaged venv should not stop the app from opening at all.
        print(f"  could not use it ({exc}); continuing with {sys.executable}",
              file=sys.stderr)


def _unlock_account() -> None:
    """Ask for the password, and the code, before anything needs the key.

    This runs before `core.do_config` is imported anywhere, because that
    module derives the signing account the moment it loads. An install with no
    keyvault.json -- everyone who has not chosen a password -- passes straight
    through.
    """
    from core import ft_unlock

    ready, problem = ft_unlock.unlock_app_key(_this_dir, "FileTrust Data Owner")
    if ready:
        return
    if problem == "cancelled":
        raise SystemExit(1)
    message = (
        f"The app could not be unlocked: {problem}.\n\n"
        "The account key is in keyvault.json, encrypted with your password. "
        "Nobody can recover that password -- not us, and not a reinstall.\n\n"
        "If you have lost it, the account and everything stored under it are "
        "gone, and the only way forward is a new account:\n"
        "    ./install.sh --new-account"
    )
    print(f"\n{message}\n", file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("FileTrust Data Owner — locked", message)
        root.destroy()
    except Exception:
        pass
    raise SystemExit(2)


def _require_account() -> None:
    """Refuse to open the window when there is no usable account, and say why.

    install.sh offers to create an account and a user may decline, so "no key
    yet" is an expected state rather than a broken install. Without this the
    first thing they would see is a stack trace from deep inside the signing
    code, or a window whose every button fails.
    """
    from core import do_config as C

    if getattr(C, "ACCOUNT_READY", False):
        return

    where = getattr(C.config, "CONFIG_PATH", "config.json")
    message = (
        f"{C.ACCOUNT_PROBLEM}.\n\n"
        "The Data Owner app signs everything it does with your own account, so "
        "it needs one before it can open.\n\n"
        "Either let the installer create one for you:\n"
        "    ./install.sh --new-account\n\n"
        "or put your own private key into this file, as do_private_key:\n"
        f"    {where}\n\n"
        "A new account starts with no funds, and uploading costs a small fee, "
        "so it will need funding before the first upload."
    )
    print(f"\n{message}\n", file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("FileTrust Data Owner — no account yet", message)
        root.destroy()
    except Exception:
        pass  # no display: the message is on the terminal either way
    raise SystemExit(2)


_restart_in_app_environment()

if __name__ == "__main__":
    _unlock_account()
    _require_account()
    from core.do_ui import build_ui

    build_ui()
else:
    from core.do_ui import build_ui
