"""Durable, pausable VaultMesh upload jobs.

Secrets, quote linkage, and completed receipts are persisted before a transfer
is attempted so a process restart resumes one obligation instead of creating a
new escrow or deletion credential.
"""

from __future__ import annotations

import datetime
import contextlib
import os
if os.name == "nt":
    import msvcrt
else:
    import fcntl
import hashlib
import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path

from . import do_hex as HX
from . import do_secrets as SEC
from .ft_update_bootstrap import child_lock_options


class TransferPaused(RuntimeError):
    pass


class TransferPending(RuntimeError):
    """A durable transfer must resume against the same VK/escrow."""


class TransferSecurityBlocked(RuntimeError):
    """A durable VK response failed a permanent trust-boundary check."""


class TransferRouteConflict(TransferPending):
    """A VK is already reserved by another piece in this upload generation."""


_lock = threading.RLock()
_active: dict[str, subprocess.Popen] = {}
_starting: set[str] = set()
_paused_transfers: set[str] = set()
_pause_requested = threading.Event()
_digest_cache: dict[tuple[str, int, int, int, int], str] = {}
_workspace_thread_locks: dict[str, threading.RLock] = {}
_workspace_lock_state = threading.local()


def _reset_process_local_state_after_fork() -> None:
    global _lock, _active, _starting, _paused_transfers, _pause_requested
    global _workspace_thread_locks, _workspace_lock_state
    _lock = threading.RLock()
    _active = {}
    _starting = set()
    _paused_transfers = set()
    _pause_requested = threading.Event()
    _workspace_thread_locks = {}
    _workspace_lock_state = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_process_local_state_after_fork)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _jobs_dir(base_dir: str | os.PathLike) -> Path:
    root = Path(base_dir) / "transfer_jobs"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / "uploads"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


@contextlib.contextmanager
def _workspace_job_lock(base_dir: str | os.PathLike):
    """Serialize durable transfer decisions across threads and processes.

    A process-local ``RLock`` is necessary because ``flock`` ownership is tied
    to an open file description and must not be used as a thread mutex.  The
    thread-local depth map makes this context safely re-entrant when a public
    operation calls another durable operation for the same workspace.
    """
    jobs_dir = _jobs_dir(base_dir)
    lock_path = jobs_dir.parent / ".uploads.lock"
    workspace = str(lock_path.resolve())
    with _lock:
        thread_lock = _workspace_thread_locks.setdefault(
            workspace, threading.RLock()
        )
    depth_map = getattr(_workspace_lock_state, "depth", None)
    if depth_map is None:
        depth_map = {}
        _workspace_lock_state.depth = depth_map
    held = depth_map.get(workspace)
    if held is not None:
        held["depth"] += 1
        try:
            yield jobs_dir
        finally:
            held["depth"] -= 1
        return

    thread_lock.acquire()
    fd: int | None = None
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        if os.name == "nt":
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX)
        depth_map[workspace] = {"depth": 1, "fd": fd}
        yield jobs_dir
    finally:
        depth_map.pop(workspace, None)
        if fd is not None:
            try:
                if os.name == "nt":
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        thread_lock.release()


def _atomic_write(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def _file_sha256(path: str) -> str:
    stat = os.stat(path)
    cache_key = (
        str(Path(path).resolve()),
        int(stat.st_size),
        int(stat.st_mtime_ns),
        int(stat.st_ctime_ns),
        int(getattr(stat, "st_ino", 0)),
    )
    with _lock:
        cached = _digest_cache.get(cache_key)
    if cached:
        return cached
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    value = digest.hexdigest()
    with _lock:
        _digest_cache[cache_key] = value
    return value


def _stable_peer_id(peer: str) -> str:
    value = str(peer or "").strip()
    if "/p2p/" in value:
        return value.rsplit("/p2p/", 1)[-1].strip()
    return value


def _canonical_file_id(file_id: object) -> str:
    try:
        return HX.normalize_file_id(file_id)
    except ValueError as exc:
        raise TransferPending(f"invalid durable upload fileId: {exc}") from exc


def _canonical_upload_instance_id(upload_instance_id: object | None) -> str:
    value = str(upload_instance_id or "").strip()
    if not value:
        return ""
    if len(value) > 256 or any(ord(char) < 0x20 for char in value):
        raise TransferPending("invalid durable uploadInstanceId")
    return value


def _canonical_chain_namespace(chain_namespace: object | None) -> str:
    if chain_namespace in (None, ""):
        return ""
    if isinstance(chain_namespace, (dict, list, tuple)):
        try:
            value = json.dumps(
                chain_namespace, sort_keys=True, separators=(",", ":")
            )
        except (TypeError, ValueError) as exc:
            raise TransferPending("invalid durable chain namespace") from exc
    else:
        value = str(chain_namespace).strip()
    if not value or len(value) > 1024 or any(ord(char) < 0x20 for char in value):
        raise TransferPending("invalid durable chain namespace")
    return value


def _job_key(logical_job_id: str, peer: str, attempt_generation: int = 1) -> str:
    immutable = json.dumps({
        "logicalJobId": str(logical_job_id),
        "peerId": _stable_peer_id(peer),
        "attemptGeneration": int(attempt_generation),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(immutable.encode("utf-8")).hexdigest()


def _logical_job_key(file_digest: str, file_id: str, piece_index: int,
                     file_format: str, upload_instance_id: str = "",
                     chain_namespace: str = "") -> str:
    immutable = json.dumps({
        "fileDigest": str(file_digest).lower(),
        "fileId": _canonical_file_id(file_id),
        "pieceIndex": int(piece_index),
        "fileFormat": str(file_format),
        "uploadInstanceId": _canonical_upload_instance_id(upload_instance_id),
        "chainNamespace": _canonical_chain_namespace(chain_namespace),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(immutable.encode("utf-8")).hexdigest()


def _read_job(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TransferPending(f"{label} cannot be read safely") from exc
    if not isinstance(value, dict):
        raise TransferPending(f"{label} is not a JSON object")
    return value


def _job_matches_file_id(job: dict, canonical_file_id: str) -> bool:
    try:
        return _canonical_file_id(job.get("fileId", "")) == canonical_file_id
    except TransferPending:
        # A malformed durable job cannot safely be ignored: it may own escrow,
        # bytes, or a deletion secret for this workspace.
        raise


def _job_matches_scope(
    job: dict,
    upload_instance_id: str,
    chain_namespace: str,
) -> bool:
    return (
        _canonical_upload_instance_id(job.get("uploadInstanceId"))
        == upload_instance_id
        and _canonical_chain_namespace(job.get("chainNamespace"))
        == chain_namespace
    )


def _job_matches_optional_scope(
    job: dict,
    upload_instance_id: object | None,
    chain_namespace: object | None,
) -> bool:
    if upload_instance_id is not None and (
        _canonical_upload_instance_id(job.get("uploadInstanceId"))
        != _canonical_upload_instance_id(upload_instance_id)
    ):
        return False
    if chain_namespace is not None and (
        _canonical_chain_namespace(job.get("chainNamespace"))
        != _canonical_chain_namespace(chain_namespace)
    ):
        return False
    return True


def _same_logical_secret_set(jobs: list[dict]) -> bool:
    signatures = {
        (
            str(job.get("commitmentNonce", "") or "").lower(),
            str(job.get("deletionAuthSecret", "") or "").lower(),
            str((job.get("result") or {}).get("commitmentHash", "") or "").lower()
            if isinstance(job.get("result"), dict)
            else "",
        )
        for job in jobs
    }
    return len(signatures) <= 1


def _adopt_legacy_logical_job(
    jobs_dir: Path,
    *,
    destination: Path,
    logical_id: str,
    resolved_path: str,
    file_digest: str,
    file_size: int,
    canonical_file_id: str,
    piece_index: int,
    file_format: str,
    upload_instance_id: str,
    chain_namespace: str,
) -> dict | None:
    matches: list[tuple[Path, dict]] = []
    for candidate in jobs_dir.glob("logical-*.json"):
        job = _read_job(candidate, "durable logical piece job")
        if not _job_matches_file_id(job, canonical_file_id):
            continue
        if not _job_matches_scope(job, upload_instance_id, chain_namespace):
            continue
        if int(job.get("pieceIndex", 0) or 0) != int(piece_index):
            continue
        if str(job.get("fileFormat", "")) != str(file_format):
            continue
        if int(job.get("fileSize", -1)) != int(file_size):
            continue
        stored_digest = str(job.get("fileDigest", "") or "").lower()
        if stored_digest and stored_digest != str(file_digest).lower():
            continue
        matches.append((candidate, job))
    if not matches:
        return None
    if len(matches) > 1 and not _same_logical_secret_set([job for _, job in matches]):
        raise TransferPending(
            "conflicting legacy logical jobs exist for one piece; cleanup is required"
        )
    # Prefer a completed obligation over an otherwise equivalent pending copy.
    matches.sort(
        key=lambda pair: (
            str(pair[1].get("status", "")) == "completed",
            str(pair[1].get("updatedAt", "")),
        ),
        reverse=True,
    )
    source_path, job = matches[0]
    adopted = dict(job)
    old_logical_id = str(adopted.get("logicalJobId", "") or "")
    adopted.update({
        "version": max(3, int(adopted.get("version", 1) or 1)),
        "logicalJobId": logical_id,
        "legacyLogicalJobId": old_logical_id if old_logical_id != logical_id else "",
        "filePath": resolved_path,
        "fileDigest": file_digest,
        "fileSize": int(file_size),
        "fileId": canonical_file_id,
        "pieceIndex": int(piece_index),
        "fileFormat": str(file_format),
        "uploadInstanceId": upload_instance_id,
        "chainNamespace": chain_namespace,
        "updatedAt": _utc_now(),
    })
    _atomic_write(destination, adopted)
    if source_path != destination:
        source_path.unlink(missing_ok=True)
    return adopted


def _adopt_legacy_peer_job(
    jobs_dir: Path,
    *,
    destination: Path,
    job_id: str,
    logical_job: dict,
    peer: str,
    resolved_path: str,
    file_digest: str,
    canonical_file_id: str,
    piece_index: int,
    file_format: str,
    upload_instance_id: str,
    chain_namespace: str,
) -> dict | None:
    matches: list[tuple[Path, dict]] = []
    stable_peer = _stable_peer_id(peer)
    generation = int(logical_job.get("attemptGeneration", 1) or 1)
    for candidate in jobs_dir.glob("*.json"):
        if candidate.name.startswith("logical-"):
            continue
        job = _read_job(candidate, "durable upload job")
        if not _job_matches_file_id(job, canonical_file_id):
            continue
        if not _job_matches_scope(job, upload_instance_id, chain_namespace):
            continue
        if _stable_peer_id(str(job.get("peerId") or job.get("peer") or "")) != stable_peer:
            continue
        if int(job.get("pieceIndex", 0) or 0) != int(piece_index):
            continue
        if str(job.get("fileFormat", "")) != str(file_format):
            continue
        if int(job.get("attemptGeneration", 1) or 1) != generation:
            continue
        stored_digest = str(job.get("fileDigest", "") or "").lower()
        if stored_digest and stored_digest != str(file_digest).lower():
            continue
        matches.append((candidate, job))
    if not matches:
        return None
    if len(matches) > 1:
        signatures = {
            (
                str(job.get("transferId", "") or ""),
                str(job.get("commitmentNonce", "") or "").lower(),
                str(job.get("deletionAuthSecret", "") or "").lower(),
                str((job.get("escrow") or {}).get("paymentCommitment", "") or "").lower(),
            )
            for _, job in matches
        }
        if len(signatures) > 1:
            raise TransferPending(
                "conflicting legacy peer jobs exist for one piece and VK"
            )
    matches.sort(
        key=lambda pair: (
            requires_same_peer_resume(pair[1]),
            str(pair[1].get("updatedAt", "")),
        ),
        reverse=True,
    )
    source_path, job = matches[0]
    adopted = dict(job)
    adopted.update({
        "version": max(3, int(adopted.get("version", 1) or 1)),
        "jobId": job_id,
        "logicalJobId": str(logical_job["logicalJobId"]),
        "filePath": resolved_path,
        "fileDigest": file_digest,
        "fileId": canonical_file_id,
        "pieceIndex": int(piece_index),
        "fileFormat": str(file_format),
        "uploadInstanceId": upload_instance_id,
        "chainNamespace": chain_namespace,
        "peer": str(peer),
        "peerId": stable_peer,
        "updatedAt": _utc_now(),
    })
    _atomic_write(destination, adopted)
    if source_path != destination:
        source_path.unlink(missing_ok=True)
    return adopted


def _obligated_peer_for_logical_generation(
    jobs_dir: Path,
    *,
    logical_job_id: str,
    attempt_generation: int,
) -> dict | None:
    """Return the sole peer that may be resumed for this logical attempt."""
    obligated: list[dict] = []
    for candidate in jobs_dir.glob("*.json"):
        if candidate.name.startswith("logical-"):
            continue
        job = _read_job(candidate, "durable upload job")
        if str(job.get("logicalJobId", "") or "") != str(logical_job_id):
            continue
        if int(job.get("attemptGeneration", 1) or 1) != int(attempt_generation):
            continue
        if _blocks_cross_vk_selection(job):
            obligated.append(job)
    return _validate_single_obligated_job(obligated)


def _validate_single_obligated_job(obligated: list[dict]) -> dict | None:
    if len(obligated) > 1:
        peers = {
            _stable_peer_id(str(job.get("peerId") or job.get("peer") or ""))
            for job in obligated
        }
        if len(peers) > 1:
            raise TransferPending(
                "multiple Vault Keepers own obligations for one logical piece; "
                "automatic retry is blocked"
            )
        # Duplicate files for one peer are also corruption unless they carry
        # exactly the same transfer identity and secret set.
        signatures = {
            (
                str(job.get("transferId", "") or ""),
                str(job.get("commitmentNonce", "") or "").lower(),
                str(job.get("deletionAuthSecret", "") or "").lower(),
            )
            for job in obligated
        }
        if len(signatures) > 1:
            raise TransferPending(
                "conflicting durable jobs exist for the obligated Vault Keeper"
            )
    return obligated[0] if obligated else None


def obligated_upload_jobs_for_logicals(
    base_dir: str | os.PathLike,
    logical_jobs: list[dict],
) -> dict[str, dict]:
    """Resolve all obligated VK jobs with one bounded directory scan."""
    if not logical_jobs:
        return {}
    with _workspace_job_lock(base_dir) as jobs_dir:
        current_by_key: dict[tuple[str, int], dict] = {}
        immutable_fields = (
            "logicalJobId",
            "fileDigest",
            "fileId",
            "pieceIndex",
            "fileFormat",
            "uploadInstanceId",
            "chainNamespace",
            "attemptGeneration",
            "commitmentNonce",
            "deletionAuthSecret",
        )
        for logical_job in logical_jobs:
            logical_id = str(logical_job.get("logicalJobId", "") or "")
            if not logical_id:
                raise TransferPending("logical piece has no durable logicalJobId")
            path = jobs_dir / f"logical-{logical_id}.json"
            if not path.is_file():
                raise TransferPending("durable logical piece job is missing")
            current = _read_job(path, "durable logical piece job")
            for field in immutable_fields:
                if current.get(field) != logical_job.get(field):
                    raise TransferPending(
                        "logical piece changed while selecting obligated VK: "
                        + field
                    )
            key = (
                logical_id,
                int(current.get("attemptGeneration", 1) or 1),
            )
            if key in current_by_key:
                raise TransferPending("duplicate logical piece in routing plan")
            current_by_key[key] = current

        grouped: dict[tuple[str, int], list[dict]] = {
            key: [] for key in current_by_key
        }
        for candidate in jobs_dir.glob("*.json"):
            if candidate.name.startswith("logical-"):
                continue
            job = _read_job(candidate, "durable upload job")
            key = (
                str(job.get("logicalJobId", "") or ""),
                int(job.get("attemptGeneration", 1) or 1),
            )
            if key in grouped and _blocks_cross_vk_selection(job):
                grouped[key].append(job)

        resolved: dict[str, dict] = {}
        for (logical_id, _generation), jobs in grouped.items():
            obligated = _validate_single_obligated_job(jobs)
            if obligated is not None:
                resolved[logical_id] = dict(obligated)
        return resolved


def obligated_upload_job_for_logical(
    base_dir: str | os.PathLike,
    logical_job: dict,
) -> dict | None:
    """Return the one VK job that must be resumed for this logical piece.

    Discovery order is intentionally irrelevant here.  Once escrow, bytes, or
    a VK response may exist, only the durably selected peer is a legal retry.
    """
    logical_id = str(logical_job.get("logicalJobId", "") or "")
    return obligated_upload_jobs_for_logicals(
        base_dir, [logical_job]
    ).get(logical_id)


_TERMINAL_JOB_STATUSES = frozenset({
    "expired", "deleted_confirmed", "cancelled_preobligation"
})


def _job_is_settled(job: dict) -> bool:
    """True when a job is spent: it owns no bytes, escrow, or secret any more."""
    return str(job.get("status", "")) in _TERMINAL_JOB_STATUSES


def _blocks_cross_vk_selection(job: dict) -> bool:
    if str(job.get("status", "")) in {
        "expired", "deleted_confirmed", "cancelled_preobligation"
    }:
        return False
    # A newly selected peer is reserved even before escrow/bytes.  It may be
    # released only by the explicit pre-obligation discard/cancel path; this
    # prevents two concurrent workers from selecting different VKs.
    if bool(job.get("peerSelectionReserved")):
        return True
    return requires_same_peer_resume(job)


def _reject_ambiguous_unscoped_obligation(
    jobs_dir: Path,
    *,
    canonical_file_id: str,
    piece_index: int,
    file_format: str,
    file_digest: str,
    upload_instance_id: str,
    chain_namespace: str,
) -> None:
    """Do not silently detach upgraded identities from legacy obligations."""
    if not upload_instance_id and not chain_namespace:
        return
    for candidate in jobs_dir.glob("*.json"):
        if candidate.name.startswith("logical-"):
            continue
        job = _read_job(candidate, "durable upload job")
        if job.get("uploadInstanceId") or job.get("chainNamespace"):
            continue
        if not _job_matches_file_id(job, canonical_file_id):
            continue
        if int(job.get("pieceIndex", 0) or 0) != int(piece_index):
            continue
        if str(job.get("fileFormat", "")) != str(file_format):
            continue
        stored_digest = str(job.get("fileDigest", "") or "").lower()
        if stored_digest and stored_digest != file_digest.lower():
            continue
        if str(job.get("status", "")) not in {
            "expired", "deleted_confirmed", "cancelled_preobligation"
        }:
            raise TransferPending(
                "an unscoped legacy transfer may own this piece obligation; "
                "reconcile it before using uploadInstanceId/chainNamespace"
            )


def get_or_create_logical_piece_job(
    base_dir: str | os.PathLike,
    file_path: str,
    file_id: str,
    piece_index: int,
    service_end: int,
    file_format: str,
    *,
    upload_instance_id: object | None = None,
    chain_namespace: object | None = None,
) -> dict:
    """Return the durable logical piece lifecycle for one upload instance.

    The optional scope fields intentionally default to the legacy namespace so
    existing callers continue to locate their existing jobs.  Production
    callers should provide both values.
    """
    with _workspace_job_lock(base_dir) as jobs_dir:
        return _get_or_create_logical_piece_job_locked(
            jobs_dir,
            file_path,
            file_id,
            piece_index,
            service_end,
            file_format,
            upload_instance_id=upload_instance_id,
            chain_namespace=chain_namespace,
        )


def _get_or_create_logical_piece_job_locked(
    jobs_dir: Path,
    file_path: str,
    file_id: str,
    piece_index: int,
    service_end: int,
    file_format: str,
    *,
    upload_instance_id: object | None,
    chain_namespace: object | None,
) -> dict:
    resolved_path = str(Path(file_path).resolve())
    source_stat = os.stat(resolved_path)
    canonical_file_id = _canonical_file_id(file_id)
    canonical_upload_instance_id = _canonical_upload_instance_id(
        upload_instance_id
    )
    canonical_chain_namespace = _canonical_chain_namespace(chain_namespace)
    file_digest = _file_sha256(resolved_path)
    logical_id = _logical_job_key(
        file_digest,
        canonical_file_id,
        piece_index,
        file_format,
        canonical_upload_instance_id,
        canonical_chain_namespace,
    )
    path = jobs_dir / f"logical-{logical_id}.json"
    with _lock:
        if path.is_file():
            job = _read_job(path, "durable logical piece job")
            if int(job.get("fileSize", -1)) != int(source_stat.st_size):
                raise TransferPending("logical piece source size changed")
            if str(job.get("fileDigest", "")).lower() != file_digest.lower():
                raise TransferPending("logical piece source content changed")
            if not _job_matches_file_id(job, canonical_file_id):
                raise TransferPending("logical piece fileId changed")
            if not _job_matches_scope(
                job,
                canonical_upload_instance_id,
                canonical_chain_namespace,
            ):
                raise TransferPending("logical piece upload or chain scope changed")
            if str(job.get("filePath", "")) != resolved_path or job.get("fileId") != canonical_file_id:
                job["filePath"] = resolved_path
                job["fileId"] = canonical_file_id
                job["updatedAt"] = _utc_now()
                _atomic_write(path, job)
            return job
        adopted = _adopt_legacy_logical_job(
            jobs_dir,
            destination=path,
            logical_id=logical_id,
            resolved_path=resolved_path,
            file_digest=file_digest,
            file_size=int(source_stat.st_size),
            canonical_file_id=canonical_file_id,
            piece_index=piece_index,
            file_format=file_format,
            upload_instance_id=canonical_upload_instance_id,
            chain_namespace=canonical_chain_namespace,
        )
        if adopted is not None:
            return adopted
        now = _utc_now()
        _nonce, _deletion_secret = SEC.pair(
            file_id=canonical_file_id,
            upload_instance_id=canonical_upload_instance_id,
            piece_index=piece_index,
            attempt=1,
        )
        job = {
            "version": 3,
            "logicalJobId": logical_id,
            "status": "pending",
            "filePath": resolved_path,
            "fileDigest": file_digest,
            "fileSize": int(source_stat.st_size),
            "fileId": canonical_file_id,
            "pieceIndex": int(piece_index),
            "serviceEnd": int(service_end),
            "fileFormat": str(file_format),
            "uploadInstanceId": canonical_upload_instance_id,
            "chainNamespace": canonical_chain_namespace,
            "attemptGeneration": 1,
            # Derived from the account key, not random: the same piece gives
            # the same two secrets on any machine, so losing this file no
            # longer costs the owner the ability to delete or to dispute.
            "commitmentNonce": _nonce,
            "deletionAuthSecret": _deletion_secret,
            "createdAt": now,
            "updatedAt": now,
        }
        _atomic_write(path, job)
        return job


def complete_logical_piece_job(base_dir: str | os.PathLike, logical_job: dict,
                               result: dict) -> None:
    with _workspace_job_lock(base_dir) as jobs_dir:
        completed = dict(logical_job)
        completed.update({
            "status": "completed",
            "result": result,
            "winningPeerId": str(result.get("peerId", "")),
            "updatedAt": _utc_now(),
        })
        path = jobs_dir / f"logical-{completed['logicalJobId']}.json"
        _atomic_write(path, completed)
        logical_job.clear()
        logical_job.update(completed)


def rotate_logical_piece_attempt(base_dir: str | os.PathLike, logical_job: dict) -> None:
    """Create fresh hidden lifecycle secrets only after the previous attempt was
    atomically expired and refunded on-chain."""
    with _workspace_job_lock(base_dir) as jobs_dir:
        updated = dict(logical_job)
        attempt = int(updated.get("attemptGeneration", 1)) + 1
        rotated_nonce, rotated_secret = SEC.pair(
            file_id=updated.get("fileId", ""),
            upload_instance_id=updated.get("uploadInstanceId", ""),
            piece_index=updated.get("pieceIndex", 0),
            attempt=attempt,
        )
        updated.update({
            "status": "pending",
            # The attempt number is part of the derivation, so a retry gets
            # fresh secrets exactly as it did when they were random.
            "commitmentNonce": rotated_nonce,
            "deletionAuthSecret": rotated_secret,
            "attemptGeneration": attempt,
            "updatedAt": _utc_now(),
        })
        updated.pop("result", None)
        updated.pop("winningPeerId", None)
        path = jobs_dir / f"logical-{updated['logicalJobId']}.json"
        _atomic_write(path, updated)
        logical_job.clear()
        logical_job.update(updated)


def reset_logical_piece_after_confirmed_deletion(
    base_dir: str | os.PathLike,
    logical_job_id: str,
) -> None:
    """Allow the same logical piece to be stored again after verified deletion."""
    logical_job_id = str(logical_job_id or "").strip()
    if not logical_job_id:
        raise TransferPending("deleted piece is missing its durable logical job id")
    with _workspace_job_lock(base_dir) as jobs_dir:
        path = jobs_dir / f"logical-{logical_job_id}.json"
        if not path.is_file():
            raise TransferPending("deleted piece logical job is missing")
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise TransferPending("deleted piece logical job cannot be read safely") from exc
        if str(job.get("status", "")) != "completed":
            return
        rotate_logical_piece_attempt(base_dir, job)


def store_authorization_message(*, transfer_id: str, file_path: str, file_id: str,
                                piece_index: int, size: int, service_end: int,
                                commitment_nonce: str, payment_commitment: str,
                                deletion_auth_hash: str, file_format: str,
                                uploader: str, issued_at: int,
                                expected_piece_root: str = "",
                                piece_block_size: int = 0) -> str:
    normalized_file_id = "0x" + _canonical_file_id(file_id)
    lines = [
        "FileTrust VaultMesh STORE",
        f"transferId={transfer_id}",
        f"fileId={normalized_file_id}",
        f"pieceIndex={int(piece_index)}",
        f"name={os.path.basename(file_path)}",
        f"size={int(size)}",
        f"serviceEnd={int(service_end)}",
        f"commitmentNonce={str(commitment_nonce).strip().lower()}",
        f"paymentCommitment={str(payment_commitment).strip().lower()}",
        f"deletionAuthHash={str(deletion_auth_hash).strip().lower()}",
        f"fileFormat={file_format}",
    ]
    expected_root_input = str(expected_piece_root or "").strip()
    if expected_root_input:
        try:
            expected_root = HX.prefixed_hex(
                expected_root_input,
                expected_bytes=32,
                field="expectedPieceRoot",
            )
        except ValueError as exc:
            raise TransferPending(str(exc)) from exc
        if int(piece_block_size or 0) <= 0:
            raise TransferPending(
                "pieceBlockSize must be positive when expectedPieceRoot is signed"
            )
        lines.extend([
            f"expectedPieceRoot={expected_root}",
            f"pieceBlockSize={int(piece_block_size)}",
        ])
    lines.extend([
        f"uploader={uploader}",
        f"issuedAt={int(issued_at)}",
    ])
    return "\n".join(lines)


def get_or_create_upload_job(
    base_dir: str | os.PathLike,
    file_path: str,
    peer: str,
    file_id: str,
    piece_index: int,
    service_end: int,
    file_format: str,
    *,
    upload_instance_id: object | None = None,
    chain_namespace: object | None = None,
) -> dict:
    """Atomically select a VK and create/read its durable transfer job."""
    with _workspace_job_lock(base_dir) as jobs_dir:
        return _get_or_create_upload_job_locked(
            jobs_dir,
            file_path,
            peer,
            file_id,
            piece_index,
            service_end,
            file_format,
            upload_instance_id=upload_instance_id,
            chain_namespace=chain_namespace,
        )


def reserve_unique_upload_jobs(
    base_dir: str | os.PathLike,
    reservations: list[dict],
) -> list[dict]:
    """Atomically reserve distinct on-chain VKs for sibling file pieces.

    Planning in the caller is advisory.  This operation is the durable commit
    point and is serialized across threads and processes.  It prevents two
    concurrent upload invocations from assigning one VK (including two peer
    IDs for the same VK address) to different pieces of the same RIDA upload.
    """
    if not reservations:
        return []

    prepared: list[dict] = []
    requested_pieces: set[int] = set()
    requested_addresses: set[str] = set()
    for raw in reservations:
        item = dict(raw)
        piece_index = int(item.get("pieceIndex", 0) or 0)
        if piece_index <= 0 or piece_index in requested_pieces:
            raise TransferPending("upload routing contains an invalid piece index")
        requested_pieces.add(piece_index)
        peer = str(item.get("peer", "") or "").strip()
        peer_id = _stable_peer_id(peer)
        if not peer_id:
            raise TransferPending("upload routing contains an empty Vault Keeper peer")
        try:
            vk_address = HX.prefixed_hex(
                item.get("vkAddress", ""),
                expected_bytes=20,
                field="selected VK address",
            ).lower()
        except ValueError as exc:
            raise TransferPending(str(exc)) from exc
        if vk_address in requested_addresses:
            raise TransferRouteConflict(
                "two upload pieces were assigned to the same on-chain Vault Keeper"
            )
        requested_addresses.add(vk_address)
        item["pieceIndex"] = piece_index
        item["peer"] = peer
        item["peerId"] = peer_id
        item["vkAddress"] = vk_address
        item["fileId"] = _canonical_file_id(item.get("fileId", ""))
        item["uploadInstanceId"] = _canonical_upload_instance_id(
            item.get("uploadInstanceId")
        )
        item["chainNamespace"] = _canonical_chain_namespace(
            item.get("chainNamespace")
        )
        prepared.append(item)

    scope = {
        (
            item["fileId"], item["uploadInstanceId"], item["chainNamespace"]
        )
        for item in prepared
    }
    if len(scope) != 1:
        raise TransferPending("upload routing reservations do not share one scope")
    file_id, upload_instance_id, chain_namespace = next(iter(scope))

    with _workspace_job_lock(base_dir) as jobs_dir:
        # Map peer IDs from this authoritative discovery snapshot to addresses
        # so legacy jobs can be migrated without weakening address uniqueness.
        address_by_peer = {
            item["peerId"]: item["vkAddress"] for item in prepared
        }
        owner_by_address: dict[str, tuple[int, str]] = {}
        bound_by_piece: dict[int, list[dict]] = {}
        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            if not _job_matches_file_id(job, file_id):
                continue
            if not _job_matches_scope(job, upload_instance_id, chain_namespace):
                continue
            if not _blocks_cross_vk_selection(job):
                continue
            peer_id = _stable_peer_id(
                str(job.get("peerId") or job.get("peer") or "")
            )
            stored_address = str(job.get("selectedVkAddress", "") or "").lower()
            if stored_address:
                try:
                    stored_address = HX.prefixed_hex(
                        stored_address,
                        expected_bytes=20,
                        field="durable selected VK address",
                    ).lower()
                except ValueError as exc:
                    raise TransferPending(str(exc)) from exc
            else:
                stored_address = address_by_peer.get(peer_id, "")
            if not stored_address:
                raise TransferPending(
                    "a durable VK reservation has no authoritative on-chain address"
                )
            piece_index = int(job.get("pieceIndex", 0) or 0)
            logical_id = str(job.get("logicalJobId", "") or "")
            previous_owner = owner_by_address.get(stored_address)
            if previous_owner is not None and previous_owner != (
                piece_index, logical_id
            ):
                raise TransferPending(
                    "durable upload state already assigns one on-chain VK to "
                    "multiple pieces"
                )
            owner_by_address[stored_address] = (piece_index, logical_id)
            bound_by_piece.setdefault(piece_index, []).append(job)

        created: list[dict] = []
        for item in sorted(prepared, key=lambda value: value["pieceIndex"]):
            piece_index = item["pieceIndex"]
            logical_id = str(item.get("logicalJobId", "") or "")
            existing = _validate_single_obligated_job(
                bound_by_piece.get(piece_index, [])
            )
            if existing is not None:
                existing_peer = _stable_peer_id(
                    str(existing.get("peerId") or existing.get("peer") or "")
                )
                if existing_peer != item["peerId"]:
                    raise TransferRouteConflict(
                        f"piece {piece_index} acquired a different durable VK "
                        "while its routing plan was being committed"
                    )
                if logical_id and str(existing.get("logicalJobId", "")) != logical_id:
                    raise TransferPending(
                        f"piece {piece_index} durable logical identity changed"
                    )
            owner = owner_by_address.get(item["vkAddress"])
            if owner is not None and owner[0] != piece_index:
                raise TransferRouteConflict(
                    f"Vault Keeper {item['vkAddress']} is already reserved by "
                    f"piece {owner[0]}"
                )
            job = _get_or_create_upload_job_locked(
                jobs_dir,
                str(item["filePath"]),
                item["peer"],
                item["fileId"],
                piece_index,
                int(item.get("serviceEnd", 0) or 0),
                str(item.get("fileFormat", "")),
                upload_instance_id=upload_instance_id,
                chain_namespace=chain_namespace,
            )
            if logical_id and str(job.get("logicalJobId", "")) != logical_id:
                raise TransferPending(
                    f"piece {piece_index} routing reservation changed logical identity"
                )
            stored_address = str(job.get("selectedVkAddress", "") or "").lower()
            if stored_address and stored_address != item["vkAddress"]:
                raise TransferPending(
                    f"piece {piece_index} routing reservation changed VK address"
                )
            if not stored_address:
                job["selectedVkAddress"] = item["vkAddress"]
                job["updatedAt"] = _utc_now()
                _atomic_write(jobs_dir / f"{job['jobId']}.json", job)
            owner_by_address[item["vkAddress"]] = (
                piece_index, str(job.get("logicalJobId", ""))
            )
            created.append(dict(job))
        return created


def _get_or_create_upload_job_locked(
    jobs_dir: Path,
    file_path: str,
    peer: str,
    file_id: str,
    piece_index: int,
    service_end: int,
    file_format: str,
    *,
    upload_instance_id: object | None,
    chain_namespace: object | None,
) -> dict:
    canonical_upload_instance_id = _canonical_upload_instance_id(
        upload_instance_id
    )
    canonical_chain_namespace = _canonical_chain_namespace(chain_namespace)
    resolved_path = str(Path(file_path).resolve())
    source_stat = os.stat(resolved_path)
    canonical_file_id = _canonical_file_id(file_id)
    file_digest = _file_sha256(resolved_path)
    _reject_ambiguous_unscoped_obligation(
        jobs_dir,
        canonical_file_id=canonical_file_id,
        piece_index=piece_index,
        file_format=file_format,
        file_digest=file_digest,
        upload_instance_id=canonical_upload_instance_id,
        chain_namespace=canonical_chain_namespace,
    )
    logical_job = _get_or_create_logical_piece_job_locked(
        jobs_dir,
        file_path,
        file_id,
        piece_index,
        service_end,
        file_format,
        upload_instance_id=canonical_upload_instance_id,
        chain_namespace=canonical_chain_namespace,
    )
    job_id = _job_key(
        str(logical_job["logicalJobId"]), peer,
        int(logical_job.get("attemptGeneration", 1)),
    )
    obligated = _obligated_peer_for_logical_generation(
        jobs_dir,
        logical_job_id=str(logical_job["logicalJobId"]),
        attempt_generation=int(logical_job.get("attemptGeneration", 1) or 1),
    )
    if obligated is not None:
        obligated_peer = _stable_peer_id(
            str(obligated.get("peerId") or obligated.get("peer") or "")
        )
        requested_peer = _stable_peer_id(peer)
        if obligated_peer and obligated_peer != requested_peer:
            raise TransferPending(
                "this logical piece already has escrow, bytes, or a response "
                f"with Vault Keeper {obligated_peer}; resume it or resolve its "
                "on-chain registration timeout before selecting another VK"
            )
    path = jobs_dir / f"{job_id}.json"
    with _lock:
        if path.is_file():
            job = _read_job(path, "durable upload job")
            if int(job.get("fileSize", -1)) != int(source_stat.st_size):
                raise TransferPending("upload source size changed after transfer job creation")
            if job.get("commitmentNonce") != logical_job.get("commitmentNonce") or \
                    job.get("deletionAuthSecret") != logical_job.get("deletionAuthSecret"):
                raise TransferPending("peer transfer secrets do not match logical piece job")
            if not _job_matches_scope(
                job,
                canonical_upload_instance_id,
                canonical_chain_namespace,
            ):
                raise TransferPending("peer transfer upload or chain scope changed")
            status = str(job.get("status", ""))
            if status in {"expired", "deleted_confirmed"}:
                raise TransferPending(
                    "closed peer transfer requires a new logical attempt generation"
                )
            if status == "cancelled_preobligation":
                # A pre-obligation cancellation RETIRES its transferId, so reviving
                # this job must mint a new one.
                #
                # The keeper binds a durable quote reservation to the transferId and
                # keeps it after the quote settles, so reviving the same id asks for
                # a new escrow deposit against a reservation that can never take
                # one. Before 2026-09-30 the keeper answered that with "busy, retry",
                # which was a wrong answer this loop then believed forever; with the
                # truthful answer it is still a dead end, just a faster one. Either
                # way the id is spent.
                #
                # Re-minting cannot pay twice, because cancellation is only permitted
                # while zero obligation is provable -- no escrow, no bytes, no
                # response, no launch. The quote commitments are dropped with the id
                # that owned them; keeping them would offer the keeper commitments
                # belonging to a different transfer.
                #
                # Live on 2026-09-30: do-01 piece 4 had burned three keepers this
                # way. Each attempt was refused, cancelled, then revived under the
                # same spent id, so no keeper was ever asked a question it could
                # still say yes to.
                job["retiredTransferIds"] = [
                    *(job.get("retiredTransferIds") or []),
                    str(job.get("transferId", "") or ""),
                ][-8:]
                job["transferId"] = "ftu_" + secrets.token_hex(24)
                job.pop("quoteInfo", None)
                job["escrow"] = {}
                job["status"] = "pending"
                job["peerSelectionReserved"] = True
                job["reselectedAt"] = _utc_now()
                job["updatedAt"] = _utc_now()
                _atomic_write(path, job)
            same_metadata = (
                int(job.get("sourceMtimeNs", -1)) == int(source_stat.st_mtime_ns)
                and int(job.get("sourceCtimeNs", -1)) == int(source_stat.st_ctime_ns)
                and int(job.get("sourceInode", -1)) == int(getattr(source_stat, "st_ino", 0))
            )
            changed = False
            if not same_metadata:
                if job.get("fileDigest") != file_digest:
                    raise TransferPending("upload source content changed after transfer job creation")
                job["sourceMtimeNs"] = int(source_stat.st_mtime_ns)
                job["sourceCtimeNs"] = int(source_stat.st_ctime_ns)
                job["sourceInode"] = int(getattr(source_stat, "st_ino", 0))
                changed = True
            # A workspace may move while the bytes and filesystem metadata stay
            # unchanged (for example after restoring a load-test workspace).
            # Canonical identity/path recovery must not depend on mtime changes.
            if str(job.get("filePath", "")) != resolved_path:
                job["filePath"] = resolved_path
                changed = True
            if str(job.get("fileId", "")) != canonical_file_id:
                job["fileId"] = canonical_file_id
                changed = True
            if changed:
                job["updatedAt"] = _utc_now()
                _atomic_write(path, job)
            return job
        adopted = _adopt_legacy_peer_job(
            jobs_dir,
            destination=path,
            job_id=job_id,
            logical_job=logical_job,
            peer=peer,
            resolved_path=resolved_path,
            file_digest=file_digest,
            canonical_file_id=canonical_file_id,
            piece_index=piece_index,
            file_format=file_format,
            upload_instance_id=canonical_upload_instance_id,
            chain_namespace=canonical_chain_namespace,
        )
        if adopted is not None:
            if adopted.get("commitmentNonce") != logical_job.get("commitmentNonce") or \
                    adopted.get("deletionAuthSecret") != logical_job.get("deletionAuthSecret"):
                raise TransferPending(
                    "adopted peer transfer secrets do not match logical piece job"
                )
            return adopted
        now = _utc_now()
        job = {
            "version": 3,
            "jobId": job_id,
            "transferId": "ftu_" + secrets.token_hex(24),
            "status": "pending",
            "filePath": resolved_path,
            "fileDigest": file_digest,
            "fileSize": int(source_stat.st_size),
            "sourceMtimeNs": int(source_stat.st_mtime_ns),
            "sourceCtimeNs": int(source_stat.st_ctime_ns),
            "sourceInode": int(getattr(source_stat, "st_ino", 0)),
            "peer": str(peer),
            "peerId": _stable_peer_id(peer),
            "fileId": canonical_file_id,
            "pieceIndex": int(piece_index),
            "serviceEnd": int(service_end),
            "fileFormat": str(file_format),
            "uploadInstanceId": canonical_upload_instance_id,
            "chainNamespace": canonical_chain_namespace,
            "logicalJobId": logical_job["logicalJobId"],
            "attemptGeneration": int(logical_job.get("attemptGeneration", 1)),
            "commitmentNonce": logical_job["commitmentNonce"],
            "deletionAuthSecret": logical_job["deletionAuthSecret"],
            "escrow": {},
            "peerSelectionReserved": True,
            "createdAt": now,
            "updatedAt": now,
        }
        _atomic_write(path, job)
        return job


def update_upload_job(base_dir: str | os.PathLike, job: dict, **updates) -> dict:
    with _workspace_job_lock(base_dir) as jobs_dir:
        job_id = str(job.get("jobId", "") or "")
        if not job_id:
            raise TransferPending("durable upload job has no jobId")
        path = jobs_dir / f"{job_id}.json"
        current = _read_job(path, "durable upload job") if path.is_file() else dict(job)
        immutable_fields = {
            "jobId", "transferId", "logicalJobId", "fileId", "pieceIndex",
            "uploadInstanceId", "chainNamespace", "attemptGeneration",
            "commitmentNonce", "deletionAuthSecret", "peerId",
        }
        for field in immutable_fields.intersection(updates):
            if updates[field] != current.get(field):
                raise TransferPending(
                    f"durable upload job immutable field changed: {field}"
                )
        if current.get("transferMayHaveReachedVK") and updates.get(
            "transferMayHaveReachedVK"
        ) is False:
            raise TransferPending(
                "transferMayHaveReachedVK cannot be cleared by a generic update"
            )
        merged = dict(current)
        merged.update(updates)
        merged["updatedAt"] = _utc_now()
        try:
            _atomic_write(path, merged)
        except Exception as exc:
            raise TransferPending("durable upload job update failed") from exc
        job.clear()
        job.update(merged)
        return job


def cancel_upload_job_before_obligation(
    base_dir: str | os.PathLike,
    job: dict,
    *,
    reason: str = "",
) -> dict:
    """Release one selected VK only while zero obligation is provable."""
    job_id = str(job.get("jobId", "") or "")
    if not job_id:
        raise TransferPending("pre-obligation cancellation has no jobId")
    with _workspace_job_lock(base_dir) as jobs_dir:
        path = jobs_dir / f"{job_id}.json"
        if not path.is_file():
            raise TransferPending("pre-obligation transfer job is missing")
        current = _read_job(path, "durable upload job")
        if str(current.get("transferId", "")) != str(job.get("transferId", "")):
            raise TransferPending("pre-obligation transfer identity changed")
        if requires_same_peer_resume(current):
            raise TransferPending(
                "VK selection cannot be cancelled after escrow, launch, bytes, or response"
            )
        if str(current.get("status", "")) == "cancelled_preobligation":
            job.clear()
            job.update(current)
            return current
        current["status"] = "cancelled_preobligation"
        current["preobligationCancelledAt"] = _utc_now()
        current["preobligationCancelReason"] = str(reason or "")
        current["updatedAt"] = _utc_now()
        _atomic_write(path, current)
        job.clear()
        job.update(current)
        return current


def _verification_pairs_dir(jobs_dir: Path) -> Path:
    path = jobs_dir.parent / "verification_pairs"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _verification_pair_id(
    logical_job_id: str,
    peer_job_id: str,
    transfer_id: str,
) -> str:
    encoded = json.dumps(
        {
            "logicalJobId": logical_job_id,
            "peerJobId": peer_job_id,
            "transferId": transfer_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _same_pair_scope(logical: dict, peer: dict) -> bool:
    return (
        str(peer.get("logicalJobId", ""))
        == str(logical.get("logicalJobId", ""))
        and _canonical_upload_instance_id(peer.get("uploadInstanceId"))
        == _canonical_upload_instance_id(logical.get("uploadInstanceId"))
        and _canonical_chain_namespace(peer.get("chainNamespace"))
        == _canonical_chain_namespace(logical.get("chainNamespace"))
        and peer.get("commitmentNonce") == logical.get("commitmentNonce")
        and peer.get("deletionAuthSecret") == logical.get("deletionAuthSecret")
        and int(peer.get("attemptGeneration", 1) or 1)
        == int(logical.get("attemptGeneration", 1) or 1)
    )


def _bind_result_to_pair(result: dict, logical: dict, peer: dict) -> dict:
    if not isinstance(result, dict):
        raise TransferPending("VK store result is not an object")
    bound = dict(result)
    expected = {
        "logicalJobId": str(logical.get("logicalJobId", "")),
        "peerJobId": str(peer.get("jobId", "")),
        "transferId": str(peer.get("transferId", "")),
        "uploadInstanceId": _canonical_upload_instance_id(
            logical.get("uploadInstanceId")
        ),
        "chainNamespace": _canonical_chain_namespace(
            logical.get("chainNamespace")
        ),
    }
    for key, value in expected.items():
        supplied = bound.get(key)
        if supplied not in (None, "") and str(supplied) != value:
            raise TransferPending(f"VK store result has conflicting {key}")
        bound[key] = value
    expected_peer = _stable_peer_id(
        str(peer.get("peerId") or peer.get("peer") or "")
    )
    supplied_peer = _stable_peer_id(
        str(bound.get("peerId") or bound.get("resolvedMultiaddr") or "")
    )
    if supplied_peer and expected_peer and supplied_peer != expected_peer:
        raise TransferPending("VK store result has conflicting peerId")
    if not bound.get("peerId"):
        bound["peerId"] = expected_peer
    return bound


def _json_value_is_subset(expected: object, actual: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _json_value_is_subset(value, actual[key])
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return isinstance(actual, list) and expected == actual
    return expected == actual


# These fields describe verification progress, not the VK response identity.
# A response is checkpointed before any trust/chain checks so a crash cannot
# orphan an obligation.  The checks below are therefore expected to advance
# while every other field from the original response must remain byte-for-byte
# stable.
_VERIFICATION_PROGRESS_FIELDS = frozenset({
    "verificationCheckpointRevision",
    "receiptVerified",
    "commitmentHashVerified",
    "deletionAuthHashRegistered",
    "fileRegTxEventVerified",
    "fileRegOnChainVerified",
    "partitionLinkedVerified",
    "partitionLinkReason",
    "partitionProofCurrentOrGrace",
    "partitionProofReason",
    "fileRegFullyVerified",
    "registrationLifecycleStatus",
    "storageVerificationStatus",
    "storageLifecycleState",
    "storageVerificationReason",
    "escrowPendingFinalize",
    "escrowFinalizeError",
    "escrowFinalizeTx",
    "escrowFinalizeWei",
})


def _pending_result_matches_progressed_result(
    pending_result: object,
    progressed_result: object,
) -> bool:
    """Match immutable response evidence while allowing verification progress."""
    if not isinstance(pending_result, dict) or not isinstance(
        progressed_result, dict
    ):
        return False
    return all(
        key in progressed_result
        and value == progressed_result[key]
        for key, value in pending_result.items()
        if key not in _VERIFICATION_PROGRESS_FIELDS
    )


def _verification_results_have_no_immutable_conflict(
    first: object,
    second: object,
) -> bool:
    """Return true when all shared immutable response fields are identical."""
    if not isinstance(first, dict) or not isinstance(second, dict):
        return False
    shared = set(first).intersection(second).difference(
        _VERIFICATION_PROGRESS_FIELDS
    )
    return all(first[key] == second[key] for key in shared)


def mark_piece_jobs_pending_verification(
    base_dir: str | os.PathLike,
    logical_job: dict,
    peer_job: dict,
    result: dict,
) -> dict:
    """Durably bind an unverified VK response to one exact job pair."""
    logical_id = str(logical_job.get("logicalJobId", "") or "")
    peer_job_id = str(peer_job.get("jobId", "") or "")
    transfer_id = str(peer_job.get("transferId", "") or "")
    if not logical_id or not peer_job_id or not transfer_id:
        raise TransferPending("verification pair is missing durable identifiers")
    with _workspace_job_lock(base_dir) as jobs_dir:
        logical_path = jobs_dir / f"logical-{logical_id}.json"
        peer_path = jobs_dir / f"{peer_job_id}.json"
        if not logical_path.is_file() or not peer_path.is_file():
            raise TransferPending("verification pair durable job is missing")
        logical = _read_job(logical_path, "durable logical piece job")
        peer = _read_job(peer_path, "durable upload job")
        if str(peer.get("transferId", "")) != transfer_id:
            raise TransferPending("verification pair transferId changed")
        if not _same_pair_scope(logical, peer):
            raise TransferPending("verification pair scope or secrets do not match")
        bound_result = _bind_result_to_pair(result, logical, peer)
        logical_status = str(logical.get("status", ""))
        peer_status = str(peer.get("status", ""))
        if logical_status == "completed" or peer_status == "completed":
            logical_result = (
                logical.get("result") if isinstance(logical.get("result"), dict)
                else {}
            )
            peer_result = (
                peer.get("result") if isinstance(peer.get("result"), dict)
                else {}
            )
            if (
                logical_status == peer_status == "completed"
                and _pending_result_matches_progressed_result(
                    bound_result, logical_result
                )
                and _pending_result_matches_progressed_result(
                    bound_result, peer_result
                )
            ):
                result.clear()
                result.update(logical_result)
                return dict(logical_result)
            raise TransferPending(
                "verification pair has an inconsistent completed checkpoint"
            )
        terminal = {"expired", "deleted_confirmed", "cancelled_preobligation"}
        if logical_status in terminal or peer_status in terminal:
            raise TransferPending(
                "verification pair was already closed by another lifecycle"
            )
        pair_id = _verification_pair_id(logical_id, peer_job_id, transfer_id)
        marker_path = _verification_pairs_dir(jobs_dir) / f"{pair_id}.json"
        if marker_path.is_file():
            marker = _read_job(marker_path, "durable verification pair")
            if str(marker.get("phase", "")) == "completing":
                raise TransferPending(
                    "verification pair completion is already in progress; "
                    "run verified-result reconciliation"
                )
            previous = marker.get("pendingResult")
            if not _verification_results_have_no_immutable_conflict(
                previous, bound_result
            ):
                raise TransferPending(
                    "verification pair already contains a different VK result"
                )
            current_revision = int(
                marker.get("checkpointRevision", 0)
                or (previous or {}).get("verificationCheckpointRevision", 0)
                or 0
            )
            incoming_revision = int(
                bound_result.get("verificationCheckpointRevision", 0) or 0
            )
            revision_is_current = incoming_revision == current_revision
            legacy_migration = current_revision == 0 and incoming_revision == 0
            if not (revision_is_current or legacy_migration):
                # Another verifier advanced this checkpoint after the caller
                # read it. Never let a stale thread regress trust/finality
                # fields; return the current durable state for reconciliation.
                current_result = dict(previous)
                result.clear()
                result.update(current_result)
                logical_job.clear()
                logical_job.update(logical)
                peer_job.clear()
                peer_job.update(peer)
                return current_result
            checkpoint_result = dict(previous)
            checkpoint_result.update(bound_result)
        else:
            if int(bound_result.get("verificationCheckpointRevision", 0) or 0):
                raise TransferPending(
                    "new verification checkpoint has an unexpected revision"
                )
            current_revision = 0
            checkpoint_result = dict(bound_result)
            marker = {
                "version": 1,
                "pairId": pair_id,
                "phase": "pending_verification",
                "logicalJobId": logical_id,
                "peerJobId": peer_job_id,
                "transferId": transfer_id,
                "uploadInstanceId": logical.get("uploadInstanceId", ""),
                "chainNamespace": logical.get("chainNamespace", ""),
                "createdAt": _utc_now(),
            }
        next_revision = current_revision + 1
        checkpoint_result["verificationCheckpointRevision"] = next_revision
        marker["checkpointRevision"] = next_revision
        marker["pendingResult"] = checkpoint_result
        marker["updatedAt"] = _utc_now()
        _atomic_write(marker_path, marker)

        logical["status"] = "pending_verification"
        logical["pendingVerificationResult"] = checkpoint_result
        logical["updatedAt"] = _utc_now()
        _atomic_write(logical_path, logical)
        peer["status"] = "pending_verification"
        # A checkpointed VK response is conclusive evidence that the transfer
        # reached that VK, even when recovering a legacy/directly-written job
        # which lacks the earlier process-launch flag.
        peer["transferMayHaveReachedVK"] = True
        peer["pendingVerificationResult"] = checkpoint_result
        peer["updatedAt"] = _utc_now()
        _atomic_write(peer_path, peer)

        logical_job.clear()
        logical_job.update(logical)
        peer_job.clear()
        peer_job.update(peer)
        result.clear()
        result.update(checkpoint_result)
        return checkpoint_result


def load_verification_pair_for_recovery(
    base_dir: str | os.PathLike,
    result: dict,
) -> tuple[dict, dict, dict]:
    """Load and validate the durable job pair behind a queued VK response."""
    if not isinstance(result, dict):
        raise TransferPending("verification recovery result is not an object")
    logical_id = str(result.get("logicalJobId", "") or "")
    peer_job_id = str(result.get("peerJobId", "") or "")
    transfer_id = str(result.get("transferId", "") or "")
    if not logical_id or not peer_job_id or not transfer_id:
        raise TransferPending(
            "verification recovery requires logicalJobId, peerJobId, and transferId"
        )
    with _workspace_job_lock(base_dir) as jobs_dir:
        logical_path = jobs_dir / f"logical-{logical_id}.json"
        peer_path = jobs_dir / f"{peer_job_id}.json"
        if not logical_path.is_file() or not peer_path.is_file():
            raise TransferPending("verification recovery durable job pair is missing")
        logical = _read_job(logical_path, "durable logical piece job")
        peer = _read_job(peer_path, "durable upload job")
        if str(peer.get("transferId", "")) != transfer_id:
            raise TransferPending("verification recovery transferId changed")
        if not _same_pair_scope(logical, peer):
            raise TransferPending(
                "verification recovery job scope or secrets do not match"
            )
        bound_result = _bind_result_to_pair(result, logical, peer)
        pair_id = _verification_pair_id(logical_id, peer_job_id, transfer_id)
        marker_path = _verification_pairs_dir(jobs_dir) / f"{pair_id}.json"
        durable_result: dict | None = None
        if marker_path.is_file():
            marker = _read_job(marker_path, "durable verification pair")
            candidate = marker.get("pendingResult")
            if isinstance(candidate, dict):
                durable_result = dict(candidate)
            elif isinstance(marker.get("verifiedResult"), dict):
                durable_result = dict(marker["verifiedResult"])
        if durable_result is None:
            logical_result = (
                logical.get("result")
                if isinstance(logical.get("result"), dict)
                else logical.get("pendingVerificationResult")
            )
            peer_result = (
                peer.get("result")
                if isinstance(peer.get("result"), dict)
                else peer.get("pendingVerificationResult")
            )
            if isinstance(logical_result, dict) and isinstance(peer_result, dict):
                if not _verification_results_have_no_immutable_conflict(
                    logical_result, peer_result
                ):
                    raise TransferPending(
                        "verification recovery job checkpoints conflict"
                    )
                durable_result = dict(logical_result)
                for key, value in peer_result.items():
                    if key not in durable_result:
                        durable_result[key] = value
        if durable_result is None:
            raise TransferPending(
                "verification recovery has no durable response checkpoint"
            )
        if not _verification_results_have_no_immutable_conflict(
            durable_result, bound_result
        ):
            raise TransferPending(
                "queued verification item conflicts with its durable VK response"
            )
        # Durable evidence wins for every existing immutable field. The queue
        # may contribute only new top-level evidence and mutable progress; all
        # trust booleans are recomputed by the caller before use.
        recovered = dict(durable_result)
        for key, value in bound_result.items():
            if key in _VERIFICATION_PROGRESS_FIELDS or key not in recovered:
                recovered[key] = value
        recovered = _bind_result_to_pair(recovered, logical, peer)
        return dict(logical), dict(peer), recovered


def complete_verified_piece_jobs(
    base_dir: str | os.PathLike,
    result: dict,
) -> dict:
    """Complete only the exact pair previously checkpointed for verification."""
    if not isinstance(result, dict):
        raise TransferPending("verified VK store result is not an object")
    required_checks = (
        "receiptVerified",
        "commitmentHashVerified",
        "deletionAuthHashRegistered",
        "fileRegOnChainVerified",
        "partitionLinkedVerified",
        "partitionProofCurrentOrGrace",
        "fileRegFullyVerified",
    )
    missing_checks = [
        field for field in required_checks if result.get(field) is not True
    ]
    if missing_checks:
        raise TransferPending(
            "storage result is not authoritatively verified: "
            + ", ".join(missing_checks)
        )
    if str(result.get("registrationLifecycleStatus", "")).lower() != (
        "onchain_confirmed"
    ):
        raise TransferPending(
            "storage result is not an on-chain-confirmed registration"
        )
    if result.get("escrowPendingFinalize") is True:
        raise TransferPending(
            "storage result escrow finalization is still pending"
        )
    logical_id = str(result.get("logicalJobId", "") or "")
    peer_job_id = str(result.get("peerJobId", "") or "")
    transfer_id = str(result.get("transferId", "") or "")
    if not logical_id or not transfer_id or not peer_job_id:
        raise TransferPending(
            "verified result requires logicalJobId, peerJobId, and transferId"
        )
    with _workspace_job_lock(base_dir) as jobs_dir:
        logical_path = jobs_dir / f"logical-{logical_id}.json"
        peer_path = jobs_dir / f"{peer_job_id}.json"
        if not logical_path.is_file() or not peer_path.is_file():
            raise TransferPending("verified result durable job pair is missing")
        logical = _read_job(logical_path, "durable logical piece job")
        peer = _read_job(peer_path, "durable upload job")
        if str(peer.get("transferId", "")) != transfer_id:
            raise TransferPending("verified result transferId does not match peer job")
        if not _same_pair_scope(logical, peer):
            raise TransferPending("verified result job scope or secrets do not match")
        bound_result = _bind_result_to_pair(result, logical, peer)
        pair_id = _verification_pair_id(logical_id, peer_job_id, transfer_id)
        marker_path = _verification_pairs_dir(jobs_dir) / f"{pair_id}.json"
        if not marker_path.is_file():
            logical_result = (
                logical.get("result") if isinstance(logical.get("result"), dict)
                else {}
            )
            peer_result = (
                peer.get("result") if isinstance(peer.get("result"), dict)
                else {}
            )
            if (
                str(logical.get("status", "")) == "completed"
                and str(peer.get("status", "")) == "completed"
                and _pending_result_matches_progressed_result(
                    bound_result, logical_result
                )
                and _pending_result_matches_progressed_result(
                    bound_result, peer_result
                )
            ):
                result.clear()
                result.update(logical_result)
                return dict(logical_result)
            raise TransferPending(
                "verified result has no durable pending-verification checkpoint"
            )
        marker = _read_job(marker_path, "durable verification pair")
        pending_result = marker.get("pendingResult")
        if not _pending_result_matches_progressed_result(
            pending_result, bound_result
        ):
            raise TransferPending("verified result differs from saved VK response")

        # The completing marker makes either file write replayable after a
        # process/power failure.  It is removed only after both checkpoints.
        marker["phase"] = "completing"
        marker["verifiedResult"] = bound_result
        marker["updatedAt"] = _utc_now()
        _atomic_write(marker_path, marker)

        peer["status"] = "completed"
        peer["result"] = bound_result
        peer.pop("pendingVerificationResult", None)
        peer["progress"] = {
            "direction": "upload",
            "bytes": int(peer.get("fileSize", 0) or 0),
            "totalBytes": int(peer.get("fileSize", 0) or 0),
        }
        peer["updatedAt"] = _utc_now()
        _atomic_write(peer_path, peer)

        logical["status"] = "completed"
        logical["result"] = bound_result
        logical["winningPeerId"] = _stable_peer_id(
            str(bound_result.get("peerId") or peer.get("peerId") or "")
        )
        logical.pop("pendingVerificationResult", None)
        logical["updatedAt"] = _utc_now()
        _atomic_write(logical_path, logical)
        marker_path.unlink(missing_ok=True)
        try:
            directory_fd = os.open(marker_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        result.clear()
        result.update(bound_result)
        return bound_result


def uploads_paused() -> bool:
    return _pause_requested.is_set()


def requires_same_peer_resume(job: dict) -> bool:
    if str(job.get("status", "")) in {
        "expired", "deleted_confirmed", "cancelled_preobligation"
    }:
        return False
    escrow = job.get("escrow") if isinstance(job.get("escrow"), dict) else {}
    if escrow.get("paymentCommitment") or escrow.get("escrowDepositTx"):
        return True
    if bool(job.get("transferMayHaveReachedVK")):
        return True
    if str(job.get("status", "pending")) in {
        "running",
        "response_received",
        "pending_verification",
        "blocked_security",
        "completed",
    }:
        return True
    progress = job.get("progress") if isinstance(job.get("progress"), dict) else {}
    return int(progress.get("bytes", 0) or 0) > 0


def file_has_storage_obligation(
    base_dir: str | os.PathLike,
    file_id: str,
    *,
    upload_instance_id: object | None = None,
    chain_namespace: object | None = None,
) -> bool:
    """Return True if changing this file's VK/IDA plan could strand an obligation."""
    normalized = _canonical_file_id(file_id)
    with _workspace_job_lock(base_dir) as jobs_dir:
        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            if not _job_matches_file_id(job, normalized):
                continue
            if not _job_matches_optional_scope(
                job, upload_instance_id, chain_namespace
            ):
                continue
            if requires_same_peer_resume(job):
                return True
    return False


def discard_file_jobs_before_obligation(
    base_dir: str | os.PathLike,
    file_id: str,
    *,
    upload_instance_id: object | None = None,
    chain_namespace: object | None = None,
) -> int:
    """Remove only transfer state proven to have no escrow, bytes, or receipt."""
    normalized = _canonical_file_id(file_id)
    with _workspace_job_lock(base_dir) as jobs_dir:
        upload_paths: list[Path] = []
        logical_ids: set[str] = set()
        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            if not _job_matches_file_id(job, normalized):
                continue
            if not _job_matches_optional_scope(
                job, upload_instance_id, chain_namespace
            ):
                continue
            if requires_same_peer_resume(job):
                raise TransferPending(
                    "storage profile cannot change after escrow, bytes, or a "
                    "receipt exists"
                )
            upload_paths.append(path)
            logical_id = str(job.get("logicalJobId", "") or "").strip()
            if logical_id:
                logical_ids.add(logical_id)

        logical_paths: list[Path] = []
        for logical_id in logical_ids:
            logical_path = jobs_dir / f"logical-{logical_id}.json"
            if logical_path.is_file():
                logical = _read_job(logical_path, "durable logical piece job")
                if str(logical.get("status", "pending")) == "completed":
                    raise TransferPending(
                        "completed logical storage cannot be discarded"
                    )
                logical_paths.append(logical_path)

        # Every related record has now been audited. Only then mutate state.
        removed = 0
        for path in upload_paths + logical_paths:
            path.unlink(missing_ok=True)
            removed += 1
        if removed:
            try:
                directory_fd = os.open(jobs_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        return removed


def unresolved_storage_jobs(
    base_dir: str | os.PathLike,
    *,
    file_id: object | None = None,
    upload_instance_id: object | None = None,
    chain_namespace: object | None = None,
) -> list[dict]:
    """Return durable attempts that may own escrow, bytes, or a VK response.

    Completed jobs are represented by the piece journal and are not returned.
    Every other obligated state must be reconciled before a load-test worker can
    report that its lifecycle has drained.
    """
    normalized = _canonical_file_id(file_id) if file_id not in (None, "") else ""
    unresolved: list[dict] = []
    with _workspace_job_lock(base_dir) as jobs_dir:
        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            if normalized and not _job_matches_file_id(job, normalized):
                continue
            if not _job_matches_optional_scope(
                job, upload_instance_id, chain_namespace
            ):
                continue
            if str(job.get("status", "")) == "completed":
                continue
            if requires_same_peer_resume(job):
                unresolved.append(dict(job))
    return unresolved


def jobs_with_escrow(base_dir: str | os.PathLike) -> list[dict]:
    """Every durable upload attempt that paid an escrow, finished or not.

    The escrow of each one is this owner's money until a keeper claims it or it is
    refunded, so the escrow reconciler looks at all of them. A job file that cannot
    be read is skipped here; the upload paths report it.
    """
    jobs: list[dict] = []
    with _workspace_job_lock(base_dir) as jobs_dir:
        for path in sorted(jobs_dir.glob("*.json")):
            if path.name.startswith("logical-"):
                continue
            try:
                job = _read_job(path, "durable upload job")
            except TransferPending:
                continue
            escrow = job.get("escrow") if isinstance(job.get("escrow"), dict) else {}
            if escrow.get("paymentCommitment"):
                jobs.append(job)
    return jobs


def storage_piece_recovery_snapshot(
    base_dir: str | os.PathLike,
    pieces_dir: str | os.PathLike,
    *,
    file_id: object,
    upload_instance_id: object,
    chain_namespace: object,
) -> dict:
    """Describe durable jobs which constrain replacement of the shared pieces.

    The caller uses this immediately before an IDA dispersal.  Completed
    logical jobs for the current upload still matter: storage may be complete
    while the DataVault batch is not, and regenerating those pieces would
    create a second hidden registration generation.  Completed jobs belonging
    to older uploads no longer need their local source and are ignored.

    Any unresolved peer job from another upload whose source is inside the
    shared pieces directory (or whose source path is missing) is returned as a
    conflict.  Clearing that directory while such a job exists could destroy
    the only local evidence needed to finish, refund, or clean up an escrow.
    """
    canonical_file_id = _canonical_file_id(file_id)
    canonical_upload = _canonical_upload_instance_id(upload_instance_id)
    canonical_chain = _canonical_chain_namespace(chain_namespace)
    pieces_root = Path(pieces_dir).resolve()

    def same_current_scope(job: dict) -> bool:
        return (
            _job_matches_file_id(job, canonical_file_id)
            and _job_matches_scope(job, canonical_upload, canonical_chain)
        )

    def path_is_in_pieces(job: dict) -> tuple[bool, bool]:
        raw = str(job.get("filePath", "") or "").strip()
        if not raw:
            return False, True
        try:
            Path(raw).resolve().relative_to(pieces_root)
        except ValueError:
            return False, False
        return True, False

    with _workspace_job_lock(base_dir) as jobs_dir:
        logical_jobs: list[dict] = []
        peer_jobs: list[dict] = []
        conflicts: list[dict] = []

        for path in jobs_dir.glob("logical-*.json"):
            job = _read_job(path, "durable logical piece job")
            if same_current_scope(job):
                logical_jobs.append(dict(job))

        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            in_pieces, path_missing = path_is_in_pieces(job)
            current = same_current_scope(job)
            if current:
                peer_jobs.append(dict(job))
                continue
            # A completed older upload is already represented by the durable
            # piece journal.  Its peer job remains an obligation for deletion
            # and accounting, but it no longer needs the local RIDA source.
            # Keep incomplete attempts fail-closed because they may still need
            # these exact bytes to resume or reconcile.
            if (
                str(job.get("status", "")) != "completed"
                and requires_same_peer_resume(job)
                and (in_pieces or path_missing)
            ):
                conflicts.append(dict(job))

        return {
            "logicalJobs": logical_jobs,
            "peerJobs": peer_jobs,
            "conflictingPeerJobs": conflicts,
            "fileId": canonical_file_id,
            "uploadInstanceId": canonical_upload,
            "chainNamespace": canonical_chain,
        }


def _normalized_optional_hash(value: object) -> str:
    return str(value or "").strip().lower()


def _job_commitment_hash(job: dict) -> str:
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    receipt = (
        result.get("privateReceipt")
        if isinstance(result.get("privateReceipt"), dict)
        else {}
    )
    return _normalized_optional_hash(
        result.get("commitmentHash")
        or receipt.get("commitmentHash")
        or job.get("commitmentHash")
    )


def settle_piece_job_after_confirmed_deletion(
    base_dir: str | os.PathLike,
    *,
    commitment_hash: str = "",
    transfer_id: str = "",
    winning_peer_id: str = "",
    logical_job_id: str = "",
) -> int:
    """Settle exactly one winning transfer after confirmed on-chain deletion.

    A commitment hash or transfer id is an exact selector.  For migrated jobs
    that lack both, the logical id and winning peer must be supplied together.
    All supplied selectors are checked; ambiguous matches fail closed.
    """
    expected_commitment = _normalized_optional_hash(commitment_hash)
    expected_transfer = str(transfer_id or "").strip()
    expected_peer = _stable_peer_id(winning_peer_id)
    logical_job_id = str(logical_job_id or "").strip()
    if not (
        expected_commitment
        or expected_transfer
        or (logical_job_id and expected_peer)
    ):
        raise TransferPending(
            "confirmed deletion settlement requires commitmentHash, transferId, "
            "or logicalJobId plus winning peer"
        )
    matches: list[tuple[Path, dict]] = []
    with _workspace_job_lock(base_dir) as jobs_dir:
        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            if logical_job_id and str(job.get("logicalJobId", "")) != logical_job_id:
                continue
            if expected_transfer and str(job.get("transferId", "")) != expected_transfer:
                continue
            job_peer = _stable_peer_id(
                str(job.get("peerId") or job.get("peer") or "")
            )
            if expected_peer and job_peer != expected_peer:
                continue
            if expected_commitment and _job_commitment_hash(job) != expected_commitment:
                continue
            matches.append((path, job))
        if len(matches) > 1:
            raise TransferPending(
                "confirmed deletion selectors match multiple durable transfers"
            )
        if not matches:
            return 0
        path, job = matches[0]
        if str(job.get("status", "")) == "deleted_confirmed":
            return 0
        job["status"] = "deleted_confirmed"
        job["deletionSettledAt"] = _utc_now()
        job["updatedAt"] = _utc_now()
        _atomic_write(path, job)

        # A confirmed deletion must not leave the winning logical result in a
        # resumable "completed" state. Rotate it only when the exact completed
        # result is the one just settled and no different peer still owns an
        # obligation for that logical generation.
        settled_logical_id = str(job.get("logicalJobId", "") or "")
        logical_path = jobs_dir / f"logical-{settled_logical_id}.json"
        if settled_logical_id and logical_path.is_file():
            logical = _read_job(logical_path, "durable logical piece job")
            logical_result = (
                logical.get("result")
                if isinstance(logical.get("result"), dict)
                else {}
            )
            logical_peer = _stable_peer_id(
                str(
                    logical_result.get("peerId")
                    or logical_result.get("resolvedMultiaddr")
                    or logical.get("winningPeerId")
                    or ""
                )
            )
            result_matches = (
                str(logical.get("status", "")) == "completed"
                and (
                    not expected_commitment
                    or _job_commitment_hash(logical) == expected_commitment
                )
                and (
                    not expected_transfer
                    or str(logical_result.get("transferId", ""))
                    == expected_transfer
                )
                and (not expected_peer or logical_peer == expected_peer)
                and _same_pair_scope(logical, job)
            )
            other_obligation = False
            if result_matches:
                for other_path in jobs_dir.glob("*.json"):
                    if other_path.name.startswith("logical-") or other_path == path:
                        continue
                    other = _read_job(other_path, "durable upload job")
                    if str(other.get("logicalJobId", "")) != settled_logical_id:
                        continue
                    if requires_same_peer_resume(other):
                        other_obligation = True
                        break
            if result_matches and not other_obligation:
                logical["status"] = "pending"
                next_attempt = int(logical.get("attemptGeneration", 1) or 1) + 1
                # Same rule as a rotation: new attempt, new secrets, and both
                # derived so they can be worked out again after a reinstall.
                logical["commitmentNonce"], logical["deletionAuthSecret"] = SEC.pair(
                    file_id=logical.get("fileId", ""),
                    upload_instance_id=logical.get("uploadInstanceId", ""),
                    piece_index=logical.get("pieceIndex", 0),
                    attempt=next_attempt,
                )
                logical["attemptGeneration"] = next_attempt
                logical["lastConfirmedDeletionAt"] = _utc_now()
                logical["lastConfirmedDeletedCommitment"] = (
                    expected_commitment or _job_commitment_hash(job)
                )
                logical.pop("result", None)
                logical.pop("winningPeerId", None)
                logical.pop("pendingVerificationResult", None)
                logical["updatedAt"] = _utc_now()
                _atomic_write(logical_path, logical)
        return 1


def settle_piece_jobs_after_confirmed_deletion(
    base_dir: str | os.PathLike,
    logical_job_id: str = "",
    *,
    commitment_hash: str = "",
    transfer_id: str = "",
    winning_peer_id: str = "",
) -> int:
    """Compatibility name for the exact, single-winner settlement API."""
    return settle_piece_job_after_confirmed_deletion(
        base_dir,
        commitment_hash=commitment_hash,
        transfer_id=transfer_id,
        winning_peer_id=winning_peer_id,
        logical_job_id=logical_job_id,
    )


def reconcile_peer_jobs_from_completed_logical(
    base_dir: str | os.PathLike,
    logical_job: dict,
    result: dict,
) -> int:
    """Repair a crash between logical and peer completion checkpoints."""
    logical_job_id = str(logical_job.get("logicalJobId", "") or "")
    if not logical_job_id:
        raise TransferPending("completed logical piece has no logicalJobId")
    winning_peer = _stable_peer_id(
        str(result.get("peerId") or result.get("resolvedMultiaddr") or "")
    )
    generation = int(logical_job.get("attemptGeneration", 1) or 1)
    repaired = 0
    with _workspace_job_lock(base_dir) as jobs_dir:
        for path in jobs_dir.glob("*.json"):
            if path.name.startswith("logical-"):
                continue
            job = _read_job(path, "durable upload job")
            if str(job.get("logicalJobId", "") or "") != logical_job_id:
                continue
            peer_id = _stable_peer_id(
                str(job.get("peerId") or job.get("peer") or "")
            )
            if winning_peer and peer_id and peer_id != winning_peer:
                if requires_same_peer_resume(job):
                    raise TransferPending(
                        "completed logical result conflicts with another "
                        "obligated Vault Keeper job"
                    )
                continue
            # Only this attempt generation is being repaired. Secrets rotate
            # with the generation, so matching on logicalJobId alone drags in
            # peer jobs from superseded attempts and compares their old secrets
            # against the current ones. _job_key and
            # _obligated_peer_for_logical_generation both key on the generation
            # for exactly this reason; this scan was the one that did not.
            #
            # Live on 2026-09-28: piece 2 was stored on a keeper at 17:44 as
            # generation 1, deleted at 19:01, then stored again on the SAME
            # keeper at 19:04 as generation 2 with fresh secrets. The
            # generation-1 tombstone still held the old ones, and because it sat
            # on the winning peer the peer_id escape above could not fire, so
            # every resume raised here instead. do-02 and do-04 retried once a
            # minute for over two hours while do-01, do-03 and do-05, which had
            # no superseded job on a winning peer, uploaded normally.
            if int(job.get("attemptGeneration", 1) or 1) != generation:
                continue
            # A settled job of this generation owns nothing and must not be
            # revived: rewriting a deleted_confirmed peer job back to completed
            # below would resurrect a piece this workspace already deleted.
            if _job_is_settled(job):
                continue
            if (
                job.get("commitmentNonce") != logical_job.get("commitmentNonce")
                or job.get("deletionAuthSecret")
                != logical_job.get("deletionAuthSecret")
            ):
                raise TransferPending(
                    "completed logical and peer jobs have different lifecycle secrets"
                )
            if str(job.get("status", "")) == "completed" and job.get("result") == result:
                continue
            job["status"] = "completed"
            job["result"] = result
            job["progress"] = {
                "direction": "upload",
                "bytes": int(job.get("fileSize", 0) or 0),
                "totalBytes": int(job.get("fileSize", 0) or 0),
            }
            job["updatedAt"] = _utc_now()
            _atomic_write(path, job)
            repaired += 1
    return repaired


def pause_uploads() -> int:
    _pause_requested.set()
    with _lock:
        processes = list(_active.items())
        _paused_transfers.update(transfer_id for transfer_id, _ in processes)
    for _, process in processes:
        if process.poll() is None:
            process.terminate()
    return len(processes)


def resume_uploads() -> None:
    _pause_requested.clear()


# Statuses that mean the job is over, one way or another. Everything else is
# work this owner started, paid toward, and has not finished.
FINISHED_JOB_STATUSES = frozenset({
    "completed", "expired", "deleted_confirmed", "cancelled_preobligation",
})


def unfinished_upload_jobs(base_dir: str | os.PathLike) -> list[dict]:
    """Durable upload jobs left incomplete, newest first.

    Read straight off disk with no chain calls: this answers the question asked
    the moment the window opens -- is there work to pick up -- and must not make
    a user wait on the network to find out.
    """
    jobs_dir = _jobs_dir(base_dir)
    if not jobs_dir.is_dir():
        return []
    out: list[dict] = []
    for path in jobs_dir.glob("*.json"):
        try:
            job = _read_job(path, "durable upload job")
        except Exception:
            continue  # a half-written job file is not a reason to refuse to start
        if str(job.get("status", "")) in FINISHED_JOB_STATUSES:
            continue
        if not str(job.get("transferId", "") or ""):
            continue
        out.append(job)
    out.sort(key=lambda j: str(j.get("updatedAt", "") or j.get("createdAt", "")), reverse=True)
    return out


def resumable_upload_peers(
    base_dir: str | os.PathLike, upload_instance_id: str
) -> list[str]:
    """Every Vault Keeper route this upload already owes work to.

    An interrupted upload has already negotiated terms and paid escrow to a
    particular keeper for each piece, so which keeper holds which piece is a
    fact recorded on disk, not a choice to make again -- asking the user to
    pick keepers to resume is asking them to answer a settled question, and
    picking a different one would abandon paid escrow.

    Finished jobs count too: the routing plan is built for every piece of the
    upload, so the keepers of the pieces that already arrived have to be in
    the list beside the keepers of the pieces that did not.
    """
    wanted = _canonical_upload_instance_id(upload_instance_id).lower()
    if not wanted:
        return []
    jobs_dir = _jobs_dir(base_dir)
    if not jobs_dir.is_dir():
        return []
    routes: list[str] = []
    seen: set[str] = set()
    for path in sorted(jobs_dir.glob("*.json")):
        try:
            job = _read_job(path, "durable upload job")
        except Exception:
            continue
        try:
            found = _canonical_upload_instance_id(job.get("uploadInstanceId"))
        except TransferPending:
            continue
        if found.lower() != wanted:
            continue
        route = str(job.get("peer") or "").strip()
        peer_id = str(job.get("peerId") or _stable_peer_id(route) or "").strip()
        if not route or not peer_id or peer_id in seen:
            continue
        seen.add(peer_id)
        routes.append(route)
    return routes


def run_upload_process(base_dir: str | os.PathLike, job: dict, cmd: list[str],
                       progress_callback=None) -> str:
    if _pause_requested.is_set():
        update_upload_job(base_dir, job, status="paused")
        raise TransferPaused("upload paused before admission")
    transfer_id = str(job["transferId"])
    deadline = time.monotonic() + 10
    while True:
        with _lock:
            already_active = transfer_id in _active or transfer_id in _starting
            if not already_active:
                _starting.add(transfer_id)
                break
        if time.monotonic() >= deadline:
            raise TransferPending("this upload transfer is already active")
        time.sleep(0.05)
    try:
        # This checkpoint is deliberately before Popen.  Once process creation
        # is attempted, a crash cannot prove that the VK received zero bytes.
        # Only an explicit timeout/cancel/deletion lifecycle may release it.
        update_upload_job(
            base_dir,
            job,
            status="starting",
            transferMayHaveReachedVK=True,
            transferLaunchPreparedAt=_utc_now(),
            lastError="",
        )
    except Exception:
        with _lock:
            _starting.discard(transfer_id)
        raise
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            **child_lock_options(),
        )
    except Exception as exc:
        with _lock:
            _starting.discard(transfer_id)
        update_upload_job(
            base_dir,
            job,
            status="pending",
            lastError=f"upload process could not start: {exc}",
        )
        raise TransferPending(f"upload process could not start: {exc}") from exc
    stderr_lines: list[str] = []
    last_progress_persisted = 0.0

    def _drain_stderr() -> None:
        nonlocal last_progress_persisted
        assert process.stderr is not None
        for line in process.stderr:
            stripped = line.rstrip()
            stderr_lines.append(stripped)
            if stripped.startswith("FILETRUST_PROGRESS "):
                try:
                    progress = json.loads(stripped.split(" ", 1)[1])
                    now = time.monotonic()
                    complete = int(progress.get("bytes", 0)) >= int(progress.get("totalBytes", 1))
                    if complete or now-last_progress_persisted >= 5:
                        update_upload_job(base_dir, job, progress=progress, status="running")
                        last_progress_persisted = now
                    if progress_callback:
                        progress_callback(progress)
                except Exception:
                    pass

    with _lock:
        _starting.discard(transfer_id)
        _active[transfer_id] = process
        paused_after_start = _pause_requested.is_set()
        if paused_after_start:
            _paused_transfers.add(transfer_id)
    if paused_after_start and process.poll() is None:
        process.terminate()
    try:
        update_upload_job(base_dir, job, status="running", lastError="")
    except Exception:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)
        with _lock:
            _active.pop(transfer_id, None)
        raise
    drain = threading.Thread(target=_drain_stderr, daemon=True)
    drain.start()
    assert process.stdout is not None
    stdout = process.stdout.read()
    return_code = process.wait()
    drain.join(timeout=2)
    process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    with _lock:
        _active.pop(transfer_id, None)

    with _lock:
        was_paused = transfer_id in _paused_transfers
        _paused_transfers.discard(transfer_id)
    if was_paused and return_code != 0:
        update_upload_job(base_dir, job, status="paused")
        raise TransferPaused("upload paused; resume uses the same transfer and escrow")
    if return_code != 0:
        error = "\n".join(line for line in stderr_lines if not line.startswith("FILETRUST_PROGRESS ")).strip()
        error = error or stdout.strip() or f"VaultMesh exited with status {return_code}"
        update_upload_job(base_dir, job, status="pending", lastError=error)
        raise TransferPending(error)
    update_upload_job(
        base_dir, job, status="response_received", rawStoreResponse=stdout.strip(),
    )
    return stdout.strip()
