# do_tray.py - optional system tray integration for the DO app.

import threading
import tkinter as tk
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import do_log as L
from . import do_state as S


def _run_on_tk_thread(func) -> None:
    if S.root is None:
        return
    try:
        S.root.after(0, func)
    except Exception:
        pass


def _show_window(icon=None, item=None) -> None:
    def show() -> None:
        if S.root is None:
            return
        S.root.deiconify()
        S.root.lift()
        try:
            S.root.focus_force()
        except Exception:
            pass

    _run_on_tk_thread(show)


def hide_window_to_tray(icon=None, item=None) -> None:
    def hide() -> None:
        if S.root is None:
            return
        if S.tray_available:
            S.root.withdraw()
            L.set_status("Running in system tray", "ready")
        else:
            S.root.destroy()

    _run_on_tk_thread(hide)


def _open_drop_folder(icon=None, item=None) -> None:
    def open_folder() -> None:
        try:
            from . import do_actions as A

            A.open_drop_folder()
        except Exception as exc:
            L.log(f"Could not open drop folder from tray: {exc}")

    _run_on_tk_thread(open_folder)


def _update_network_settings(icon=None, item=None) -> None:
    """Ask the network config service for the current chain settings.

    By hand, from the tray, rather than on a timer: the answer carries every
    ABI on the chain and the addresses in it change a few times a year, so
    polling would cost one small server a great deal for nothing. It is also
    the honest moment to ask -- the user knows the network was redeployed, or
    has been told their calls are failing.

    The fetch runs off the window thread, and the result is reported on it.
    New addresses take effect at the next start, because the contract objects
    this app talks through are built while it loads.
    """
    import threading
    from pathlib import Path

    def work() -> None:
        base = Path(__file__).resolve().parents[1]
        try:
            from . import ft_netconfig

            changed, problem = ft_netconfig.refresh(base)
        except Exception as exc:                      # never crash the tray
            changed, problem = [], str(exc)
        if problem:
            title, body = "Network settings", (
                f"The network settings could not be read.\n\n{problem}\n\n"
                "Nothing was changed; the app keeps the settings it has."
            )
        elif changed:
            title, body = "Network settings", (
                f"Updated {len(changed)} setting(s) from the network:\n\n"
                + "\n".join(f"  - {name}" for name in changed[:12])
                + ("\n  ..." if len(changed) > 12 else "")
                + "\n\nRestart the app for them to take effect."
            )
        else:
            title, body = "Network settings", "Already up to date."
        try:
            L.log(body.splitlines()[0])
        except Exception:
            pass   # a log that cannot write must not swallow the answer

        def report() -> None:
            from tkinter import messagebox

            messagebox.showinfo(title, body)

        _run_on_tk_thread(report)

    try:
        L.log("Reading the network settings...")
    except Exception:
        pass
    threading.Thread(target=work, daemon=True, name="network-config").start()


def _check_application_updates(icon=None, item=None) -> None:
    def check():
        notice = getattr(S.root, "_filetrust_updates", None)
        if notice:
            notice.check()
    _run_on_tk_thread(check)


def _show_about(icon=None, item=None) -> None:
    def show_about() -> None:
        from . import do_panels
        do_panels.open_about_window()

    _run_on_tk_thread(show_about)


def _show_context_menu(x: int | None = None, y: int | None = None) -> None:
    def show_menu() -> None:
        if S.root is None:
            return
        menu = tk.Menu(S.root, tearoff=0)
        menu.add_command(label="Update network settings", command=_update_network_settings)
        menu.add_command(label="Check for app updates", command=_check_application_updates)
        menu.add_command(label="About Me", command=_show_about)
        menu.add_separator()
        menu.add_command(label="Exit", command=quit_app)
        try:
            if x is None or y is None:
                px, py = S.root.winfo_pointerxy()
            else:
                px, py = int(x), int(y)
            menu.tk_popup(px, py)
        finally:
            try:
                menu.grab_release()
            except Exception:
                pass

    _run_on_tk_thread(show_menu)


def stop_tray_icon() -> None:
    icon = S.tray_icon
    S.tray_available = False
    S.tray_icon = None
    if icon is None:
        return
    try:
        icon.stop()
    except Exception:
        pass


def quit_app(icon=None, item=None) -> None:
    stop_tray_icon()

    def close() -> None:
        if S.root is not None:
            S.root.destroy()

    _run_on_tk_thread(close)


def _make_tray_image():
    """The FileTrust mark for the tray, drawn only if the file is missing."""
    from PIL import Image, ImageDraw, ImageFont

    logo = Path(__file__).resolve().parent / "assets" / "logo.png"
    if logo.is_file():
        try:
            mark = Image.open(logo).convert("RGBA").resize((64, 64), Image.LANCZOS)
            # On a dark panel a white mark alone can vanish, so it keeps the
            # navy tile the brand uses behind it.
            tile = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            draw = ImageDraw.Draw(tile)
            draw.rounded_rectangle((0, 0, 63, 63), radius=12, fill=(31, 38, 66, 255))
            tile.alpha_composite(mark)
            return tile
        except Exception:
            pass

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((8, 8, 56, 56), radius=12, fill=(31, 38, 65, 255))
    draw.rounded_rectangle((12, 12, 52, 52), radius=10, outline=(255, 215, 0, 255), width=4)
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 22)
    except Exception:
        font = ImageFont.load_default()
    text = "FT"
    box = draw.textbbox((0, 0), text, font=font)
    x = (64 - (box[2] - box[0])) / 2
    y = (64 - (box[3] - box[1])) / 2 - 1
    draw.text((x, y), text, fill=(124, 239, 216, 255), font=font)
    return img


def _enable_system_gi() -> bool:
    """Allow the venv to use distro GI bindings when they match this Python."""
    candidates = [
        Path("/usr/lib/python3/dist-packages"),
        Path(f"/usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/dist-packages"),
    ]
    for path in candidates:
        if path.is_dir() and str(path) not in sys.path:
            sys.path.append(str(path))

    try:
        import gi  # noqa: F401

        return True
    except Exception:
        return False


def _gi_namespace_available(namespace: str, version: str) -> bool:
    try:
        import gi

        gi.require_version(namespace, version)
        __import__(f"gi.repository.{namespace}")
        return True
    except Exception:
        return False


def _prepare_pystray_backend() -> None:
    if not sys.platform.startswith("linux"):
        return
    if os.environ.get("PYSTRAY_BACKEND"):
        return
    if not _enable_system_gi():
        return
    if (
        _gi_namespace_available("AppIndicator3", "0.1")
        or _gi_namespace_available("AyatanaAppIndicator3", "0.1")
    ):
        os.environ["PYSTRAY_BACKEND"] = "appindicator"
        return
    if _gi_namespace_available("Gtk", "3.0"):
        os.environ["PYSTRAY_BACKEND"] = "gtk"


def _ensure_kde_xembed_proxy() -> None:
    if not sys.platform.startswith("linux"):
        return
    if os.environ.get("PYSTRAY_BACKEND") != "gtk":
        return
    desktop = (
        os.environ.get("XDG_CURRENT_DESKTOP", "")
        + " "
        + os.environ.get("DESKTOP_SESSION", "")
    ).lower()
    if "kde" not in desktop and "plasma" not in desktop:
        return
    proxy = shutil.which("xembedsniproxy")
    if not proxy:
        L.log("KDE tray helper xembedsniproxy was not found; GTK tray icon may stay hidden.")
        return
    try:
        running = subprocess.run(
            ["pgrep", "-x", "xembedsniproxy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
        if running:
            return
        subprocess.Popen(
            [proxy],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        L.log("Started KDE xembedsniproxy for tray icon visibility.")
    except Exception as exc:
        L.log(f"Could not start KDE xembedsniproxy tray helper: {exc}")


def _install_xorg_click_handlers(icon) -> None:
    if getattr(icon, "HAS_MENU", True):
        return
    if "._xorg" not in icon.__class__.__module__:
        return
    try:
        from Xlib import X
    except Exception as exc:
        L.log(f"Could not install Xorg tray click handlers: {exc}")
        return

    def on_button_press(event) -> None:
        if getattr(event, "detail", None) == 1:
            _show_window()
        elif getattr(event, "detail", None) == 3:
            _show_context_menu(getattr(event, "root_x", None), getattr(event, "root_y", None))

    try:
        icon._message_handlers[X.ButtonPress] = on_button_press
        L.log("System tray uses Xorg click handlers: left-click opens, right-click shows menu.")
    except Exception as exc:
        L.log(f"Could not install Xorg tray click handlers: {exc}")


def _show_log_window(icon=None, item=None) -> None:
    # Imported here, not at module load: do_panels pulls in do_actions, and the
    # tray is built long before that is finished loading.
    from . import do_panels
    _run_on_tk_thread(do_panels.open_log_window)


def _show_pieces_window(icon=None, item=None) -> None:
    from . import do_panels
    _run_on_tk_thread(do_panels.open_pieces_window)


def start_tray_icon() -> bool:
    if S.tray_available and S.tray_icon is not None:
        return True

    try:
        _prepare_pystray_backend()
        _ensure_kde_xembed_proxy()
        import pystray
        backend_name = pystray.Icon.__module__.rsplit(".", 1)[-1]
    except Exception as exc:
        S.tray_available = False
        L.log(f"System tray disabled: pystray is not installed or cannot load ({exc}).")
        return False

    try:
        menu = pystray.Menu(
            pystray.MenuItem("Open FileTrust DO", _show_window, default=True),
            # Reachable without raising the whole dashboard: these are the two
            # things a user wants to glance at while working in another window.
            pystray.MenuItem("Network Results", _show_log_window),
            pystray.MenuItem("Pieces Directory", _show_pieces_window),
            pystray.MenuItem("Update network settings", _update_network_settings),
            pystray.MenuItem("Check for app updates", _check_application_updates),
            pystray.MenuItem("About Me", _show_about),
            pystray.MenuItem("Exit", quit_app),
        )
        icon = pystray.Icon("FileTrustDO", _make_tray_image(), "FileTrust DO", menu)
        _install_xorg_click_handlers(icon)
    except Exception as exc:
        S.tray_available = False
        L.log(f"System tray disabled: could not create tray icon ({exc}).")
        return False

    def run_icon() -> None:
        try:
            icon.run()
        except Exception as exc:
            S.tray_available = False
            S.tray_icon = None
            if S.root is not None:
                S.root.after(0, lambda: L.log(f"System tray stopped: {exc}"))

    S.tray_icon = icon
    S.tray_available = True
    S.tray_thread = threading.Thread(target=run_icon, daemon=True)
    S.tray_thread.start()
    L.log(f"System tray icon started ({backend_name}).")
    return True
