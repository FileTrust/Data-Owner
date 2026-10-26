"""Process-safe transaction serialization for Data Owner signing accounts."""

from __future__ import annotations

import contextlib
import os
if os.name == "nt":
    import msvcrt
else:
    import fcntl
import functools
import os
import tempfile
import threading
from pathlib import Path
from typing import Callable


_locks_guard = threading.Lock()
_process_locks: dict[str, threading.RLock] = {}
_thread_state = threading.local()


def _normalized_address(address: str) -> str:
    normalized = str(address or "").strip().lower().removeprefix("0x")
    if not normalized or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError(f"invalid transaction signer address: {address!r}")
    return normalized


def _process_lock(address: str) -> threading.RLock:
    with _locks_guard:
        return _process_locks.setdefault(address, threading.RLock())


@contextlib.contextmanager
def account_transaction_lock(address: str, *, allow_recovery: bool = False):
    """Hold the account's transaction lane across threads and local processes."""
    normalized = _normalized_address(address)
    process_lock = _process_lock(normalized)
    with process_lock:
        depths = getattr(_thread_state, "depths", None)
        if depths is None:
            depths = {}
            _thread_state.depths = depths
        if depths.get(normalized, 0) > 0:
            depths[normalized] += 1
            try:
                yield
            finally:
                depths[normalized] -= 1
            return

        lock_dir = Path(
            os.getenv("FILETRUST_CHAIN_TX_LOCK_DIR")
            or (Path(tempfile.gettempdir()) / "filetrust-chain-tx-locks")
        )
        lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = lock_dir / f"{normalized}.lock"
        with lock_path.open("a+b") as lock_file:
            if os.name == "nt":
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            depths[normalized] = 1
            try:
                if not allow_recovery:
                    from .do_dkg_paths import require_no_pending_recovery
                    require_no_pending_recovery(address)
                yield
            finally:
                depths.pop(normalized, None)
                if os.name == "nt":
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def serialized_account(address_resolver: Callable):
    """Decorate a transaction workflow with its signer's process-safe lane."""
    def decorate(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            address = address_resolver(*args, **kwargs)
            with account_transaction_lock(address):
                return func(*args, **kwargs)
        return wrapped
    return decorate


def pending_nonce(w3, address: str) -> int:
    return int(w3.eth.get_transaction_count(address, "pending"))
