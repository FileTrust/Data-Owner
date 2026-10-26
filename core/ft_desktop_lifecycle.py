"""Let a container stop ask the existing GUI to close after active work."""
import signal
import threading


def install(root, busy, close):
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    def poll():
        if stop.is_set() and not busy():
            close()
            return
        root.after(200, poll)
    root.after(200, poll)
