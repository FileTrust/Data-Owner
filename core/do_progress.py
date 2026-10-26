# do_progress.py — one progress bar for whatever the app was asked to do.
#
# Not an upload feature. Uploading, deleting and anything else that takes long
# enough to worry a user reports through the same three calls, so the window
# needs to understand only one thing and every operation benefits from work done
# for another.
#
# An operation is a list of phases with weights. The bar advances inside a phase
# as its count rises, which is the whole point: a deletion of five pieces that
# has reached the chain with three of them is three-fifths through its second
# phase, not "pending". Weights are by effort, not by step count, so the bar
# does not leap on a cheap step and then sit still through an expensive one.

from __future__ import annotations

import threading

from . import do_state as S

_lock = threading.Lock()

# name -> (weight, done, total). Insertion order is the order they run in.
_phases: dict[str, tuple[float, int, int]] = {}
_operation = ""
_note = ""


def _publish(fraction: float, text: str, mode: str, short: str = "") -> None:
    """Hand the numbers to the window, from whichever thread we are on."""
    root = S.root
    if root is None:
        return

    def apply() -> None:
        if S.progress_bar is not None:
            try:
                S.progress_bar.set(max(0.0, min(1.0, fraction)))
            except Exception:
                pass
        if S.progress_box is not None:
            # Hidden while idle: a bar sitting at zero with nothing running
            # reads as a stalled task rather than as no task.
            try:
                S.progress_box.grid()
            except Exception:
                pass
        if S.progress_var is not None:
            S.progress_var.set(text)

    if threading.current_thread() is threading.main_thread():
        apply()
    else:
        try:
            root.after(0, apply)
        except Exception:
            pass
    # The pill keeps the short form and the caption beside the bar carries the
    # counts. Printing the same sentence in both places wasted the one piece of
    # screen that is always visible.
    from . import do_log as L  # late: do_log imports nothing from here
    L.set_status(short or text, mode)


def start(operation: str, phases: list[tuple[str, float]]) -> None:
    """Begin an operation. `phases` is [(name, weight), ...]; weights sum to 1."""
    global _operation, _note
    with _lock:
        _operation = operation
        _note = ""
        _phases.clear()
        for name, weight in phases:
            _phases[name] = (float(weight), 0, 0)
    _publish(0.0, "starting", "running", short=operation)


def step(phase: str, done: int, total: int, note: str = "") -> None:
    """Report progress inside one phase. Safe to call from any thread."""
    global _note
    with _lock:
        if phase not in _phases:
            return
        weight, _old_done, _old_total = _phases[phase]
        _phases[phase] = (weight, max(0, int(done)), max(0, int(total)))
        if note:
            _note = note
        fraction = 0.0
        for weight, phase_done, phase_total in _phases.values():
            if phase_total > 0:
                fraction += weight * min(1.0, phase_done / phase_total)
        operation, current_note = _operation, _note
        shown = f"{phase} {done}/{total}" if total else phase
    text = shown if not current_note else f"{shown} — {current_note}"
    _publish(fraction, text, "running", short=operation)


def finish(text: str = "", ok: bool = True) -> None:
    """Close the operation out. The bar stays full (or where it failed)."""
    global _operation, _note
    with _lock:
        operation = _operation
        _operation = ""
        _note = ""
        fraction = 1.0 if ok else sum(
            weight * (phase_done / phase_total if phase_total else 0.0)
            for weight, phase_done, phase_total in _phases.values()
        )
        _phases.clear()
    message = text or (f"{operation} finished" if ok else f"{operation} failed")
    _publish(fraction, message, "done" if ok else "error", short=message)


def ensure(operation: str, phases: list[tuple[str, float]]) -> None:
    """Start *operation* only if nothing is running.

    Some work is reached both inside a larger operation and on its own -- the
    guardian key exchange runs as part of an upload and also when the key is
    requested by itself. Reporting it through start() would restart the
    upload's bar; reporting it through step() alone drew nothing at all when
    it ran by itself, which is how a counting status line ended up beside an
    empty bar.
    """
    with _lock:
        if _operation:
            return
    start(operation, phases)


def is_running() -> bool:
    with _lock:
        return bool(_operation)


def running_operation() -> str:
    """The name passed to start(), or "" when nothing is running."""
    with _lock:
        return _operation
