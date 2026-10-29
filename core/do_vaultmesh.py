# do_vaultmesh.py — VaultMesh piece upload and receipt verification.

import os
import json
import datetime
import concurrent.futures
import subprocess
import threading
import time
import hashlib
import secrets
import re
import tempfile
from pathlib import Path

from eth_account.messages import encode_defunct
from web3 import Web3

from . import do_config as C
from . import do_state as S
from . import do_progress as PROG
from . import do_log as L
from . import do_records as R
from . import do_chain as CH
from . import do_txlog as TX
from . import do_tx_manager as TM
from . import do_transfer_manager as XFER
from . import do_hex as HX
from . import do_piece_journal as PJ

_escrow_tx_lock = threading.Lock()
_verification_queue_lock = threading.Lock()
_verification_reconcile_lock = threading.Lock()
_verification_reconciler_started = False
_PIECE_MERKLE_BLOCK_SIZE = 64 * 1024


def compute_piece_commitment(
    file_path: str,
    block_size: int = _PIECE_MERKLE_BLOCK_SIZE,
) -> tuple[str, str, int, int]:
    """Compute the VK protocol's merkle-sha256-v1 commitment locally.

    The leaf/node domain bytes and duplicate-last rule exactly mirror
    ``App/VK/code/merkle.go``.  The DO therefore knows the only acceptable
    piece root before any byte is sent to a VK.
    """
    if int(block_size) <= 0:
        raise ValueError("piece Merkle block size must be positive")

    def leaf(data: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + data).digest()

    def node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    whole = hashlib.sha256()
    leaves: list[bytes] = []
    size = 0
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(int(block_size))
            if not chunk:
                break
            whole.update(chunk)
            leaves.append(leaf(chunk))
            size += len(chunk)
    if not leaves:
        leaves = [leaf(b"")]
        block_count = 0
    else:
        block_count = len(leaves)
    while len(leaves) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(leaves), 2):
            left = leaves[index]
            right = leaves[index + 1] if index + 1 < len(leaves) else left
            next_level.append(node(left, right))
        leaves = next_level
    return "0x" + leaves[0].hex(), whole.hexdigest(), block_count, size


_PUBLIC_PIECE_FIELDS = {
    "name", "fileId", "uploadInstanceId", "pieceIndex", "pieceRoot",
    "peerId", "vkPeer", "resolvedMultiaddr", "size", "hashAlg", "rootAlg",
    "pieceHash", "pieceBlockSize", "pieceBlockCount", "fileFormat",
    "serviceEnd", "storageLifecycleState", "storageVerificationStatus",
    "storageVerificationReason", "fileRegFullyVerified",
    "registrationLifecycleStatus", "deletionStatus", "deleted",
}


def _public_piece_projection(item: dict) -> dict:
    """Return only DataVault routing and non-secret verification metadata."""
    return {
        key: value
        for key, value in item.items()
        if key in _PUBLIC_PIECE_FIELDS
    }


def _public_manifest_projection(manifest: dict) -> dict:
    public = {
        key: value
        for key, value in manifest.items()
        if key not in {"pieces"}
    }
    public["pieces"] = [
        _public_piece_projection(piece)
        for piece in manifest.get("pieces", [])
        if isinstance(piece, dict)
    ]
    return public


def _verification_queue_dir() -> Path:
    path = Path(C.BASE_DIR) / "storage_verification_queue"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _verification_queue_path(item: dict) -> Path:
    key = str(item.get("commitmentHash") or item.get("pieceRoot") or "").lower()
    if not key:
        raise ValueError("storage verification item has no commitmentHash or pieceRoot")
    return _verification_queue_dir() / f"{hashlib.sha256(key.encode('utf-8')).hexdigest()}.json"


def _write_json_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def queue_storage_verification(item: dict, manifest_path: str = "") -> None:
    global _verification_reconciler_started
    path = _verification_queue_path(item)
    with _verification_queue_lock:
        record = {
            "item": dict(item),
            "manifestPaths": [],
            "attempts": 0,
            "revision": 0,
        }
        if path.exists():
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise RuntimeError(
                    f"storage verification queue record is corrupt: {path}: {exc}"
                ) from exc
            if not isinstance(record, dict) or not isinstance(record.get("item"), dict):
                raise RuntimeError(
                    f"storage verification queue record has invalid structure: {path}"
                )
        record["item"] = dict(item)
        record["revision"] = int(record.get("revision", 0) or 0) + 1
        record.pop("terminal", None)
        record.pop("lastError", None)
        manifests = set(str(p) for p in record.get("manifestPaths", []) if p)
        if manifest_path:
            manifests.add(str(Path(manifest_path).resolve()))
        record["manifestPaths"] = sorted(manifests)
        record["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _write_json_atomic(path, record)
    start_storage_verification_reconciler()


def _update_manifest_verification(manifest_path: str, item: dict) -> None:
    path = Path(manifest_path)
    if not path.is_file():
        return
    manifest = json.loads(path.read_text(encoding="utf-8"))
    pieces = manifest.get("pieces") if isinstance(manifest, dict) else None
    if not isinstance(pieces, list):
        return
    for existing in pieces:
        if not isinstance(existing, dict):
            continue
        incoming_commitment = str(item.get("commitmentHash", "") or "").lower()
        existing_commitment = str(existing.get("commitmentHash", "") or "").lower()
        same_commitment = bool(
            incoming_commitment
            and existing_commitment
            and existing_commitment == incoming_commitment
        )
        # pieceRoot is only a compatibility identity for records created before
        # commitment hashes. It is not unique across multiple registrations.
        same_piece = bool(
            # Root/index is a migration key only for old projections which do
            # not yet carry a commitment hash.  Two legitimate registrations
            # may contain identical bytes, so it must never override an
            # explicit, different commitment.
            (not incoming_commitment or not existing_commitment)
            and item.get("pieceRoot")
            and str(existing.get("pieceRoot", "")).lower()
            == str(item.get("pieceRoot", "")).lower()
            and int(existing.get("pieceIndex", 0) or 0) > 0
            and int(existing.get("pieceIndex", 0) or 0)
            == int(item.get("pieceIndex", 0) or 0)
            and bool(str(item.get("uploadInstanceId", "") or ""))
            and str(existing.get("uploadInstanceId", "") or "").lower()
            == str(item.get("uploadInstanceId", "") or "").lower()
        )
        if same_commitment or same_piece:
            # Manifest projections are routing inputs. Never copy the private
            # receipt, commitment nonce, deletion secret, escrow link, or
            # journal internals out of the protected lifecycle store.
            existing.update(_public_piece_projection(item))
            break
    verified = sum(1 for piece in pieces if piece.get("fileRegFullyVerified") is True)
    manifest["storageVerification"] = {
        "status": "verified" if verified == len(pieces) else "pending",
        "lifecycleState": "fully_verified" if verified == len(pieces) else "verification_pending",
        "storedPieces": len(pieces),
        "verifiedPieces": verified,
        "totalPieces": len(pieces),
    }
    _write_json_atomic(path, manifest)


def _reconcile_pending_storage_verifications_unlocked() -> tuple[int, int]:
    completed = 0
    pending = 0
    with _verification_queue_lock:
        paths = list(_verification_queue_dir().glob("*.json"))
    for path in paths:
        record = None
        item = None
        start_revision = 0
        try:
            with _verification_queue_lock:
                record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or not isinstance(record.get("item"), dict):
                raise RuntimeError("verification queue record has invalid structure")
            if record.get("terminal") is True:
                pending += 1
                continue
            start_revision = int(record.get("revision", 0) or 0)
            queued_item = dict(record.get("item") or {})
            logical_job, peer_job, item = XFER.load_verification_pair_for_recovery(
                C.BASE_DIR, queued_item
            )
            pair_completed = (
                str(logical_job.get("status", "")) == "completed"
                and str(peer_job.get("status", "")) == "completed"
                and isinstance(logical_job.get("result"), dict)
            )
            if pair_completed:
                item = dict(logical_job["result"])
            else:
                if C.storage_proof_sc is None or C.file_registration_sc is None:
                    raise XFER.TransferPending(
                        "storage verification contracts are not configured"
                    )
                _reverify_durable_store_response(
                    item,
                    logical_job,
                    peer_job,
                    file_path=str(peer_job.get("filePath") or item.get("path") or ""),
                    peer=str(peer_job.get("peer") or peer_job.get("peerId") or ""),
                    file_id_hex=str(peer_job.get("fileId") or item.get("fileId") or ""),
                    piece_index=int(peer_job.get("pieceIndex", 0) or 0),
                    service_end=int(peer_job.get("serviceEnd", 0) or 0),
                    vk_expected_address=_vk_address_from_peer(
                        str(peer_job.get("peer") or peer_job.get("peerId") or "")
                    ),
                    chain_id=int(C.w3.eth.chain_id),
                    storage_proof_contract=str(C.storage_proof_sc.address),
                    file_registration_contract=str(C.file_registration_sc.address),
                )
            ok, reason = confirm_registration_finality(item)
            if ok and item.get("escrowPendingFinalize"):
                _finalize_escrow_if_needed(item)
            # Verification state belongs in the permanent lifecycle journal;
            # pid_records manifests are only current-upload projections.
            PJ.record_registration(
                C.BASE_DIR,
                item,
                source="storage-verification-reconciler",
            )
            if ok:
                XFER.complete_verified_piece_jobs(C.BASE_DIR, item)
            record["item"] = item
            record["attempts"] = int(record.get("attempts", 0)) + 1
            record["lastReason"] = reason
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            record["updatedAt"] = now
            if ok and not item.get("escrowPendingFinalize"):
                with _verification_queue_lock:
                    latest = record
                    if path.exists():
                        latest = json.loads(path.read_text(encoding="utf-8"))
                        if not isinstance(latest, dict):
                            raise RuntimeError(
                                "verification queue record changed to invalid data"
                            )
                    manifests = sorted(set(
                        list(record.get("manifestPaths", []))
                        + list(latest.get("manifestPaths", []))
                    ))
                    for manifest_path in manifests:
                        _update_manifest_verification(manifest_path, item)
                    path.unlink(missing_ok=True)
                completed += 1
            else:
                with _verification_queue_lock:
                    latest = record
                    if path.exists():
                        latest = json.loads(path.read_text(encoding="utf-8"))
                        if not isinstance(latest, dict) or not isinstance(
                            latest.get("item"), dict
                        ):
                            raise RuntimeError(
                                "verification queue record changed to invalid data"
                            )
                    latest_revision = int(latest.get("revision", 0) or 0)
                    if latest_revision == start_revision:
                        outgoing = record
                    else:
                        # A foreground verifier queued newer state while this
                        # chain read was in flight. Keep its item verbatim.
                        outgoing = latest
                        outgoing["attempts"] = max(
                            int(outgoing.get("attempts", 0) or 0),
                            int(record.get("attempts", 0) or 0),
                        )
                        outgoing["lastReason"] = reason
                    outgoing["lastReconciledAt"] = now
                    outgoing["revision"] = latest_revision + 1
                    _write_json_atomic(path, outgoing)
                pending += 1
        except Exception as exc:
            try:
                if isinstance(record, dict):
                    with _verification_queue_lock:
                        latest = record
                        if path.exists():
                            latest = json.loads(path.read_text(encoding="utf-8"))
                        if not isinstance(latest, dict):
                            raise RuntimeError(
                                "verification queue record changed to invalid data"
                            )
                        latest_revision = int(latest.get("revision", 0) or 0)
                        terminal = isinstance(exc, XFER.TransferSecurityBlocked)
                        if terminal:
                            # Cryptographic failure is permanent for this exact
                            # immutable response. Retain it for operator action
                            # but never hammer the chain once per minute.
                            latest["item"] = dict(
                                item
                                if isinstance(item, dict)
                                else (record or {}).get("item")
                                or latest.get("item")
                                or {}
                            )
                            latest["terminal"] = True
                            latest["status"] = "blocked_security"
                        latest["lastError"] = str(exc)
                        latest["lastReconciledAt"] = (
                            datetime.datetime.now(datetime.timezone.utc).isoformat()
                        )
                        latest["revision"] = latest_revision + 1
                        _write_json_atomic(path, latest)
                else:
                    L.log(
                        "[file_reg] verification queue record cannot be read "
                        f"safely path={path}: {exc}"
                    )
            except Exception:
                pass
            pending += 1
    return completed, pending


def reconcile_pending_storage_verifications() -> tuple[int, int]:
    with _verification_reconcile_lock:
        return _reconcile_pending_storage_verifications_unlocked()


def wait_for_manifest_storage_verification(manifest_path: str, timeout_seconds: int = 300) -> tuple[bool, str]:
    deadline = time.monotonic() + max(1, int(timeout_seconds))
    path = Path(manifest_path)
    while time.monotonic() < deadline:
        reconcile_pending_storage_verifications()
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            pieces = manifest.get("pieces") or []
            if pieces and all(item.get("fileRegFullyVerified") is True for item in pieces):
                return True, f"all {len(pieces)} pieces fully verified"
        except Exception as exc:
            last_reason = str(exc)
        else:
            pending_reasons = [
                str(item.get("storageVerificationReason") or "pending")
                for item in pieces
                if item.get("fileRegFullyVerified") is not True
            ]
            last_reason = "; ".join(pending_reasons[:3]) or "verification pending"
        time.sleep(5)
    reason = last_reason if 'last_reason' in locals() else "verification timed out"
    try:
        stored_count = len(pieces)
    except Exception:
        stored_count = 0
    return False, (
        f"{stored_count} pieces stored; trust verification pending: {reason}"
    )


def start_storage_verification_reconciler() -> None:
    global _verification_reconciler_started
    with _verification_queue_lock:
        if _verification_reconciler_started:
            return
        _verification_reconciler_started = True

    def _loop() -> None:
        while True:
            try:
                reconcile_pending_storage_verifications()
            except Exception as exc:
                L.log(f"[file_reg] verification reconciler error: {exc}")
            time.sleep(60)

    threading.Thread(
        target=_loop,
        name="storage-verification-reconciler",
        daemon=True,
    ).start()


def _config_bool(name: str, default: bool) -> bool:
    raw = getattr(C.config, name, default)
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _config_int(name: str, default: int) -> int:
    try:
        return int(getattr(C.config, name, default))
    except Exception:
        return int(default)


def _hybrid_escrow_enabled() -> bool:
    return _config_bool("DO_ESCROW_HYBRID_MODE", False)


def _hybrid_bond_wei(total_wei: int) -> int:
    if total_wei <= 1:
        return max(1, total_wei)
    bps = _config_int("DO_ESCROW_BOND_BPS", 1000)
    if bps < 1:
        bps = 1
    if bps > 9000:
        bps = 9000
    bond = (total_wei * bps) // 10000
    if bond <= 0:
        bond = 1
    if bond >= total_wei:
        bond = total_wei - 1
    return bond


def peer_id_from_peer(peer: str) -> str:
    """Return the stable peerID from either a bare peerID or a full multiaddr."""
    value = str(peer or "").strip()
    if "/p2p/" in value:
        return value.rsplit("/p2p/", 1)[-1].strip()
    return value


def get_vk_peer_from_gui(show_error: bool = True) -> str | None:
    # Import here to avoid circular at module level
    from . import do_network as N
    peers = N.get_selected_vk_peers()

    if not peers:
        if show_error:
            L.show_error(
                "VaultMesh Peer Error",
                "Please select at least one registered Vault Keeper or enter a Vault Keeper peer multiaddr.\n\n"
                "Example: /ip4/127.0.0.1/tcp/4001/p2p/12D3..."
            )
        return None

    return peers[0]


def run_vaultmesh_cmd(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def generate_commitment_nonce() -> str:
    """Return a 0x-prefixed random 32-byte hex nonce for DO to send to VK."""
    return "0x" + secrets.token_hex(32)


def _to_0x_hex(value) -> str:
    hx = value.hex()
    return hx if str(hx).startswith("0x") else "0x" + hx


def compute_deletion_auth_hash(secret_hex: str) -> str:
    """Return keccak256(bytes32(secret_hex)) as a 0x-prefixed hash."""
    secret = HX.hex_to_bytes(
        secret_hex, expected_bytes=32, field="deletion authorization secret"
    )
    return _to_0x_hex(Web3.keccak(primitive=secret))


def build_vaultmesh_store_auth(
    transfer_id: str,
    file_path: str,
    file_id: str,
    piece_index: int,
    size: int,
    service_end: int,
    commitment_nonce: str,
    payment_commitment: str,
    deletion_auth_hash: str,
    file_format: str,
    *,
    expected_piece_root: str = "",
    piece_block_size: int = 0,
) -> tuple[str, int, str]:
    uploader = C.w3.to_checksum_address(C.DO_ACCOUNT.address)
    issued_at = int(time.time())
    message = XFER.store_authorization_message(
        transfer_id=transfer_id, file_path=file_path, file_id=file_id,
        piece_index=piece_index, size=size, service_end=service_end,
        commitment_nonce=commitment_nonce, payment_commitment=payment_commitment,
        deletion_auth_hash=deletion_auth_hash, file_format=file_format,
        uploader=uploader, issued_at=issued_at,
        expected_piece_root=expected_piece_root,
        piece_block_size=piece_block_size,
    )
    signed = C.DO_ACCOUNT.sign_message(encode_defunct(text=message))
    return uploader, issued_at, signed.signature.hex()


def quote_authorization_message(
    *,
    transfer_id: str,
    file_id: str,
    size: int,
    service_end: int,
    vk_address: str,
    uploader: str,
    issued_at: int,
) -> str:
    """The exact text the keeper verifies before it holds any capacity.

    Must match vaultmeshQuoteAuthMessage in the keeper byte for byte; both sides
    pin it in a test. It names the keeper being asked, so a keeper that receives
    it cannot replay it to another keeper to hold capacity there in this data
    owner's name.
    """
    return "\n".join([
        "FileTrust VaultMesh QUOTE",
        f"transferId={transfer_id}",
        f"fileId={HX.prefixed_file_id(file_id)}",
        f"size={int(size)}",
        f"serviceEnd={int(service_end)}",
        f"vaultKeeper={Web3.to_checksum_address(vk_address)}",
        f"uploader={Web3.to_checksum_address(uploader)}",
        f"issuedAt={int(issued_at)}",
    ])


def build_vaultmesh_quote_auth(
    transfer_id: str,
    file_id: str,
    size: int,
    service_end: int,
    vk_address: str,
) -> tuple[str, int, str]:
    """Sign a quote request so the keeper can check, on chain, that it comes
    from the owner of a real file whose key generation is finished.

    A keeper holds capacity for every quote it issues, before any payment. An
    unsigned request let anyone hold it for free; the keeper now refuses one.
    """
    uploader = Web3.to_checksum_address(C.DO_ACCOUNT.address)
    issued_at = int(time.time())
    message = quote_authorization_message(
        transfer_id=transfer_id, file_id=file_id, size=size,
        service_end=service_end, vk_address=vk_address,
        uploader=uploader, issued_at=issued_at,
    )
    signed = C.DO_ACCOUNT.sign_message(encode_defunct(text=message))
    return uploader, issued_at, signed.signature.hex()


def build_vaultmesh_delete_auth(commitment_hash: str) -> tuple[str, int, str]:
    """Sign a deletion so the VK can tell who is asking, and when.

    The deletion secret proves only that the sender holds something. It carries
    no identity and never expires, so a copy taken from a log or an old backup
    would destroy the data years later. This adds the two facts the secret
    cannot carry: which wallet is asking, and that the request is current.
    """
    requester = C.w3.to_checksum_address(C.DO_ACCOUNT.address)
    issued_at = int(time.time())
    message = "\n".join([
        "FileTrust VaultMesh DELETE",
        f"commitmentHash={str(commitment_hash).strip().lower()}",
        f"requester={requester}",
        f"issuedAt={issued_at}",
    ])
    signed = C.DO_ACCOUNT.sign_message(encode_defunct(text=message))
    return requester, issued_at, signed.signature.hex()


def compute_commitment_hash(piece_root_hex: str, nonce_hex: str) -> str:
    """Return keccak256(abi.encodePacked(pieceRoot, nonce)) as 0x hex."""
    combined = HX.hex_to_bytes(
        piece_root_hex, expected_bytes=32, field="pieceRoot"
    ) + HX.hex_to_bytes(
        nonce_hex, expected_bytes=32, field="commitmentNonce"
    )
    return _to_0x_hex(Web3.keccak(primitive=combined))


def verify_commitment_hash(piece_root_hex: str, nonce_hex: str, expected_hash: str) -> tuple[bool, str]:
    """Verify that keccak256(pieceRoot || nonce) equals the expected commitmentHash."""
    if not piece_root_hex or not nonce_hex or not expected_hash:
        return False, "missing piece_root, nonce, or expected_hash"
    try:
        computed = compute_commitment_hash(piece_root_hex, nonce_hex)
        expected = HX.prefixed_hex(
            expected_hash, expected_bytes=32, field="commitmentHash"
        )
    except ValueError as exc:
        return False, f"invalid commitment input: {exc}"
    if computed != expected:
        return False, (
            f"commitmentHash mismatch: computed={computed[:18]}... "
            f"expected={expected[:18]}..."
        )
    return True, "ok"


def verify_file_registration_onchain(commitment_hash: str, receipt: dict) -> tuple[bool, str]:
    """Query FileRegistrationSC.getRecord() and verify it matches the receipt."""
    if C.file_registration_sc is None:
        return False, "FileRegistrationSC is not configured"
    def record_field(record, name: str, index: int):
        try:
            return record[name]
        except Exception:
            pass
        try:
            return getattr(record, name)
        except Exception:
            pass
        return record[index]

    try:
        ch_bytes = HX.hex_to_bytes(
            commitment_hash, expected_bytes=32, field="commitmentHash"
        )
        record = C.file_registration_sc.functions.getRecord(ch_bytes).call()
        on_chain_vk = str(record_field(record, "vkAddress", 2)).lower()
        if on_chain_vk == "0x0000000000000000000000000000000000000000":
            return False, "no on-chain record found for commitmentHash"

        on_chain_sector_root = HX.prefixed_hex(
            record_field(record, "sectorRoot", 0),
            expected_bytes=32,
            field="on-chain sectorRoot",
        )
        receipt_sector_root = HX.prefixed_hex(
            receipt.get("sectorRoot", ""),
            expected_bytes=32,
            field="receipt sectorRoot",
        )
        if on_chain_sector_root != receipt_sector_root:
            return False, (
                f"sectorRoot mismatch: on-chain={on_chain_sector_root[:18]}... "
                f"receipt={receipt_sector_root[:18]}..."
            )
        if on_chain_vk != str(receipt.get("vkAddress", "")).strip().lower():
            return False, (
                f"vkAddress mismatch: on-chain={on_chain_vk} "
                f"receipt={receipt.get('vkAddress','')}"
            )
        if int(record_field(record, "deadlineIndex", 3)) != int(receipt.get("deadlineIndex", -1)):
            return False, (
                f"deadlineIndex mismatch: on-chain={record_field(record, 'deadlineIndex', 3)} "
                f"receipt={receipt.get('deadlineIndex')}"
            )
        if int(record_field(record, "partitionIndex", 4)) != int(receipt.get("partitionIndex", -1)):
            return False, (
                f"partitionIndex mismatch: on-chain={record_field(record, 'partitionIndex', 4)} "
                f"receipt={receipt.get('partitionIndex')}"
            )
        if int(record_field(record, "serviceEnd", 5)) != int(receipt.get("serviceEnd", -1)):
            return False, (
                f"serviceEnd mismatch: on-chain={record_field(record, 'serviceEnd', 5)} "
                f"receipt={receipt.get('serviceEnd')}"
            )
        receipt_deletion_auth_hash = str(receipt.get("deletionAuthHash", "") or "").strip()
        if receipt_deletion_auth_hash:
            on_chain_deletion_auth_hash = HX.prefixed_hex(
                record_field(record, "deletionAuthHash", 8),
                expected_bytes=32,
                field="on-chain deletionAuthHash",
            )
            receipt_deletion_auth_hash = HX.prefixed_hex(
                receipt_deletion_auth_hash,
                expected_bytes=32,
                field="receipt deletionAuthHash",
            )
            if on_chain_deletion_auth_hash != receipt_deletion_auth_hash:
                return False, (
                    f"deletionAuthHash mismatch: on-chain={on_chain_deletion_auth_hash[:18]}... "
                    f"receipt={receipt_deletion_auth_hash[:18]}..."
                )
        return True, "ok"
    except Exception as exc:
        return False, f"on-chain verification error: {exc}"


def verify_registration_tx_status(tx_hash: str) -> tuple[bool, str]:
    """Check whether the FileRegistrationSC registerFileStorage() tx was mined and succeeded."""
    if not tx_hash:
        return False, "no registrationTxHash provided"
    try:
        tx_hash_normalized = tx_hash if tx_hash.startswith("0x") else ("0x" + tx_hash)
        receipt = C.w3.eth.get_transaction_receipt(tx_hash_normalized)
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="getTransactionReceipt",
            status="success",
            transaction_hash=tx_hash_normalized,
            receipt_found=receipt is not None,
            receipt_status=getattr(receipt, "status", ""),
            block_number=getattr(receipt, "blockNumber", ""),
        )
        if receipt is None:
            return False, "tx not yet mined (pending)"
        if receipt.status == 1:
            return True, f"confirmed in block {receipt.blockNumber}"
        return False, f"tx mined but reverted in block {receipt.blockNumber}"
    except Exception as exc:
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="getTransactionReceipt",
            status="failed",
            error=str(exc),
            transaction_hash=tx_hash,
        )
        return False, f"tx status check error: {exc}"


# keccak256("FileStorageRegistered(bytes32,bytes32,address,uint8,uint8,uint64)")
_FILE_STORAGE_REGISTERED_TOPIC: str = Web3.keccak(
    text="FileStorageRegistered(bytes32,bytes32,address,uint8,uint8,uint64)"
).hex()


def verify_registration_tx_event(
    tx_hash: str,
    receipt: dict,
) -> tuple[bool, str]:
    """Verify the FileStorageRegistered event emitted in registrationTxHash."""
    if not tx_hash:
        return False, "no registrationTxHash to verify"
    if C.file_registration_sc is None:
        return False, "FileRegistrationSC is not configured"

    try:
        tx_hash_norm = tx_hash if tx_hash.startswith("0x") else ("0x" + tx_hash)
        tx_rec = C.w3.eth.get_transaction_receipt(tx_hash_norm)
    except Exception as exc:
        return False, f"get_transaction_receipt error: {exc}"

    if tx_rec is None:
        return False, "tx pending (not yet mined)"

    if tx_rec.status != 1:
        return False, f"tx reverted in block {tx_rec.blockNumber}"

    fr_addr = C.file_registration_sc.address.lower()
    tx_to = str(tx_rec.get("to", "") or "").lower()
    if tx_to != fr_addr:
        return False, (
            f"tx destination mismatch: tx.to={tx_to} "
            f"expected FileRegistrationSC={fr_addr}"
        )

    event_log = None
    for log_entry in tx_rec.logs:
        if (
            log_entry.address.lower() == fr_addr
            and len(log_entry.topics) == 4
            and log_entry.topics[0].hex() == _FILE_STORAGE_REGISTERED_TOPIC
        ):
            event_log = log_entry
            break

    if event_log is None:
        return False, "FileStorageRegistered event not found in tx receipt logs"

    try:
        ev_commitment_hash = HX.prefixed_hex(
            event_log.topics[1], expected_bytes=32, field="event commitmentHash"
        )
        ev_sector_root = HX.prefixed_hex(
            event_log.topics[2], expected_bytes=32, field="event sectorRoot"
        )
        ev_vk_topic = HX.normalize_hex(
            event_log.topics[3], expected_bytes=32, field="event vkAddress topic"
        )
    except ValueError as exc:
        return False, f"invalid registration event topic: {exc}"
    ev_vk_address = "0x" + ev_vk_topic[-40:]

    data = bytes(event_log.data)
    if len(data) < 96:
        return False, f"event data too short: {len(data)} bytes (expected 96)"
    ev_deadline_index  = int.from_bytes(data[0:32],  "big")
    ev_partition_index = int.from_bytes(data[32:64], "big")
    ev_service_end     = int.from_bytes(data[64:96], "big")

    r_commitment_hash  = str(receipt.get("commitmentHash",  "")).strip().lower()
    r_sector_root      = str(receipt.get("sectorRoot",      "")).strip().lower()
    r_vk_address       = str(receipt.get("vkAddress",       "")).strip().lower()
    r_deadline_index   = int(receipt.get("deadlineIndex",   -1))
    r_partition_index  = int(receipt.get("partitionIndex",  -1))
    r_service_end      = int(receipt.get("serviceEnd",       0))

    mismatches = []
    try:
        ev_commitment_norm = HX.normalize_hex(
            ev_commitment_hash, expected_bytes=32, field="event commitmentHash"
        )
        receipt_commitment_norm = HX.normalize_hex(
            r_commitment_hash, expected_bytes=32, field="receipt commitmentHash"
        )
        ev_sector_norm = HX.normalize_hex(
            ev_sector_root, expected_bytes=32, field="event sectorRoot"
        )
        receipt_sector_norm = HX.normalize_hex(
            r_sector_root, expected_bytes=32, field="receipt sectorRoot"
        )
        ev_vk_norm = HX.normalize_hex(
            ev_vk_address, expected_bytes=20, field="event vkAddress"
        )
        receipt_vk_norm = HX.normalize_hex(
            r_vk_address, expected_bytes=20, field="receipt vkAddress"
        )
    except ValueError as exc:
        return False, f"invalid event or receipt field: {exc}"

    if ev_commitment_norm != receipt_commitment_norm:
        mismatches.append(
            f"commitmentHash: event={ev_commitment_hash[:20]}... receipt={r_commitment_hash[:20]}..."
        )
    if ev_sector_norm != receipt_sector_norm:
        mismatches.append(
            f"sectorRoot: event={ev_sector_root[:20]}... receipt={r_sector_root[:20]}..."
        )
    if ev_vk_norm != receipt_vk_norm:
        mismatches.append(
            f"vkAddress: event={ev_vk_address} receipt={r_vk_address}"
        )
    if ev_deadline_index != r_deadline_index:
        mismatches.append(
            f"deadlineIndex: event={ev_deadline_index} receipt={r_deadline_index}"
        )
    if ev_partition_index != r_partition_index:
        mismatches.append(
            f"partitionIndex: event={ev_partition_index} receipt={r_partition_index}"
        )
    if ev_service_end != r_service_end:
        mismatches.append(
            f"serviceEnd: event={ev_service_end} receipt={r_service_end}"
        )

    if mismatches:
        return False, "event field mismatch: " + "; ".join(mismatches)

    return True, f"ok (block {tx_rec.blockNumber})"


def _verification_item_matches_current_namespace(item: dict) -> tuple[bool, str]:
    """Prevent a persisted response from being verified on another deployment."""
    if C.w3 is None or C.file_registration_sc is None:
        return False, "current FileRegistrationSC chain namespace is unavailable"
    try:
        current_chain = int(C.w3.eth.chain_id)
        current_contract = HX.prefixed_hex(
            C.file_registration_sc.address,
            expected_bytes=20,
            field="current FileRegistrationSC",
        ).lower()
        stored_chain_raw = item.get("chainId", "")
        stored_contract_raw = str(
            item.get("fileRegistrationContract", "") or ""
        )
        has_chain = stored_chain_raw not in (None, "", 0, "0")
        has_contract = bool(stored_contract_raw.strip())
        if has_chain != has_contract:
            return False, "storage item contains a partial chain namespace"
        receipt = item.get("privateReceipt")
        receipt = receipt if isinstance(receipt, dict) else {}
        receipt_chain = int(receipt.get("chainId", 0) or 0)
        if receipt_chain and receipt_chain != current_chain:
            return False, "VK receipt belongs to a different blockchain"
        if has_chain:
            stored_chain = int(stored_chain_raw)
            stored_contract = HX.prefixed_hex(
                stored_contract_raw,
                expected_bytes=20,
                field="storage item FileRegistrationSC",
            ).lower()
            if (
                stored_chain != current_chain
                or stored_contract != current_contract
            ):
                return False, (
                    "storage item belongs to a different blockchain or "
                    "FileRegistrationSC"
                )
        elif not receipt_chain:
            return False, (
                "legacy storage item has no chainId and cannot be verified "
                "against the current deployment"
            )
    except Exception as exc:
        return False, f"chain namespace verification error: {exc}"
    return True, "ok"


def confirm_registration_finality(item: dict) -> tuple[bool, str]:
    """Verify registration, partition linkage, and the current proof/grace state."""
    tx_hash     = item.get("registrationTxHash", "")
    receipt     = item.get("privateReceipt", {})
    commit_hash = item.get("commitmentHash", "")

    if not commit_hash:
        item["fileRegFullyVerified"] = False
        item["storageVerificationStatus"] = "pending"
        item["storageLifecycleState"] = "verification_pending"
        return False, "no commitmentHash in item — cannot confirm"

    namespace_ok, namespace_reason = _verification_item_matches_current_namespace(
        item
    )
    if not namespace_ok:
        item["fileRegFullyVerified"] = False
        item["storageVerificationStatus"] = "pending"
        item["storageLifecycleState"] = "verification_pending"
        item["storageVerificationReason"] = namespace_reason
        return False, namespace_reason

    reasons: list[str] = []

    if tx_hash:
        ev_ok, ev_reason = verify_registration_tx_event(tx_hash, receipt)
        if not ev_ok:
            item["fileRegTxEventVerified"] = False
            if "pending" not in ev_reason:
                reasons.append(f"tx event: {ev_reason}")
        else:
            item["fileRegTxEventVerified"] = True
            L.log(f"[file_reg] tx event verified  txHash={tx_hash[:18]}...  {ev_reason}")
    else:
        item["fileRegTxEventVerified"] = None

    if item.get("receiptVerified") is not True:
        reasons.append("VK receipt signature is not verified")
    if item.get("commitmentHashVerified") is not True:
        reasons.append("commitmentHash is not verified from pieceRoot and DO nonce")

    if receipt:
        rec_ok, rec_reason = verify_file_registration_onchain(commit_hash, receipt)
        if not rec_ok:
            reasons.append(f"on-chain record: {rec_reason}")
        else:
            L.log(f"[file_reg] on-chain record confirmed  commitmentHash={commit_hash[:18]}...")
    else:
        rec_ok = False
        reasons.append("private VK receipt is missing")

    partition_link_ok = False
    partition_link_reason = "file registration not verified"
    partition_proof_ok = False
    partition_proof_reason = "partition not linked"
    if rec_ok:
        partition_link_ok, partition_link_reason = CH.check_partition_linked_onchain(commit_hash)
        if partition_link_ok:
            partition_proof_ok, partition_proof_reason = CH.verify_partition_current_onchain(
                commit_hash, receipt
            )

    item["fileRegOnChainVerified"] = bool(rec_ok)
    item["registrationLifecycleStatus"] = (
        "onchain_confirmed" if rec_ok else "onchain_pending"
    )
    item["partitionLinkedVerified"] = bool(partition_link_ok)
    item["partitionLinkReason"] = partition_link_reason
    item["partitionProofCurrentOrGrace"] = bool(partition_proof_ok)
    item["partitionProofReason"] = partition_proof_reason
    if not partition_link_ok:
        reasons.append(f"partition link: {partition_link_reason}")
    elif not partition_proof_ok:
        reasons.append(f"partition proof: {partition_proof_reason}")

    if reasons:
        item["fileRegFullyVerified"] = False
        item["storageVerificationStatus"] = "pending"
        item["storageLifecycleState"] = "verification_pending"
        item["storageVerificationReason"] = "; ".join(reasons)
        return False, "; ".join(reasons)

    item["fileRegFullyVerified"] = True
    item["storageVerificationStatus"] = "verified"
    item["storageLifecycleState"] = "fully_verified"
    item["storageVerificationReason"] = partition_proof_reason
    return True, "file registered, partition linked, and current proof/grace verified"


def _block_store_security_verification(item: dict, job: dict, reason: str) -> None:
    """Durably retain a received obligation that failed a trust check."""
    item["fileRegFullyVerified"] = False
    item["storageVerificationStatus"] = "blocked"
    item["storageLifecycleState"] = "security_blocked"
    item["registrationLifecycleStatus"] = "blocked_security"
    item["storageVerificationReason"] = str(reason)
    PJ.record_registration(
        C.BASE_DIR,
        item,
        source="vaultmesh-store-security-block",
    )
    XFER.update_upload_job(
        C.BASE_DIR,
        job,
        status="blocked_security",
        securityVerificationError=str(reason),
    )


def _reverify_durable_store_response(
    item: dict,
    logical_job: dict,
    job: dict,
    *,
    file_path: str,
    peer: str,
    file_id_hex: str,
    piece_index: int,
    service_end: int,
    vk_expected_address: str,
    chain_id: int,
    storage_proof_contract: str,
    file_registration_contract: str,
) -> None:
    """Cryptographically rebuild the local trust checks after a restart.

    Boolean fields in a durable checkpoint are never trusted.  The source
    commitment, logical secrets, selected peer, signed VK receipt, and chain
    namespace are checked again before finality may advance.
    """

    def fail(reason: str) -> None:
        _block_store_security_verification(item, job, reason)
        raise XFER.TransferSecurityBlocked(reason)

    try:
        expected_root, expected_hash, expected_blocks, expected_size = (
            compute_piece_commitment(file_path, _PIECE_MERKLE_BLOCK_SIZE)
        )
        canonical_file_id = HX.normalize_file_id(file_id_hex)
        expected_contract = HX.prefixed_hex(
            file_registration_contract,
            expected_bytes=20,
            field="FileRegistrationSC",
        ).lower()
        item_contract = HX.prefixed_hex(
            item.get("fileRegistrationContract", ""),
            expected_bytes=20,
            field="stored FileRegistrationSC",
        ).lower()
        expected_nonce = HX.prefixed_hex(
            logical_job.get("commitmentNonce", ""),
            expected_bytes=32,
            field="logical commitmentNonce",
        ).lower()
        expected_delete_secret = HX.prefixed_hex(
            logical_job.get("deletionAuthSecret", ""),
            expected_bytes=32,
            field="logical deletionAuthSecret",
        ).lower()
        expected_delete_hash = compute_deletion_auth_hash(
            expected_delete_secret
        ).lower()
        expected_commitment = compute_commitment_hash(
            expected_root, expected_nonce
        ).lower()
    except Exception as exc:
        fail(f"durable storage verification inputs are invalid: {exc}")

    expected_peer = peer_id_from_peer(
        str(job.get("peer") or job.get("peerId") or peer)
    )
    item_peer = peer_id_from_peer(
        str(item.get("resolvedMultiaddr") or item.get("peerId") or "")
    )
    escrow = job.get("escrow") if isinstance(job.get("escrow"), dict) else {}
    quote_info = (
        job.get("quoteInfo") if isinstance(job.get("quoteInfo"), dict) else {}
    )
    expected_payment = str(
        escrow.get("paymentCommitment")
        or quote_info.get("paymentCommitment")
        or ""
    ).lower()
    try:
        comparisons = {
            "fileId": (
                HX.normalize_file_id(item.get("fileId", "")),
                canonical_file_id,
            ),
            "uploadInstanceId": (
                str(item.get("uploadInstanceId", "") or "").lower(),
                str(logical_job.get("uploadInstanceId", "") or "").lower(),
            ),
            "pieceIndex": (int(item.get("pieceIndex", 0) or 0), int(piece_index)),
            "chainId": (int(item.get("chainId", 0) or 0), int(chain_id)),
            "fileRegistrationContract": (item_contract, expected_contract),
            "pieceRoot": (str(item.get("pieceRoot", "")).lower(), expected_root.lower()),
            "expectedPieceRoot": (
                str(item.get("expectedPieceRoot", "")).lower(),
                expected_root.lower(),
            ),
            "responsePieceRoot": (
                str(item.get("responsePieceRoot", "")).lower(),
                expected_root.lower(),
            ),
            "size": (int(item.get("size", -1)), int(expected_size)),
            "pieceBlockSize": (
                int(item.get("pieceBlockSize", 0) or 0),
                _PIECE_MERKLE_BLOCK_SIZE,
            ),
            "pieceBlockCount": (
                int(item.get("pieceBlockCount", -1)),
                int(expected_blocks),
            ),
            "pieceHash": (
                str(item.get("pieceHash", "") or "").lower(),
                expected_hash.lower(),
            ),
            "rootAlg": (str(item.get("rootAlg", "")), "merkle-sha256-v1"),
            "hashAlg": (str(item.get("hashAlg", "")), "sha2-256"),
            "peerId": (item_peer, expected_peer),
            "serviceEnd": (
                int(item.get("serviceEnd", 0) or 0),
                int(job.get("serviceEnd", service_end) or 0),
            ),
            "transferId": (
                str(item.get("transferId", "") or ""),
                str(job.get("transferId", "") or ""),
            ),
            "peerJobId": (
                str(item.get("peerJobId", "") or ""),
                str(job.get("jobId", "") or ""),
            ),
            "logicalJobId": (
                str(item.get("logicalJobId", "") or ""),
                str(logical_job.get("logicalJobId", "") or ""),
            ),
            "sourceDigest": (
                str(item.get("sourceDigest", "") or "").lower(),
                str(logical_job.get("fileDigest", "") or "").lower(),
            ),
            "commitmentNonce": (
                str(item.get("commitmentNonce", "") or "").lower(),
                expected_nonce,
            ),
            "deletionAuthSecret": (
                str(item.get("deletionAuthSecret", "") or "").lower(),
                expected_delete_secret,
            ),
            "deletionAuthHash": (
                str(item.get("deletionAuthHash", "") or "").lower(),
                expected_delete_hash,
            ),
            "commitmentHash": (
                str(item.get("commitmentHash", "") or "").lower(),
                expected_commitment,
            ),
        }
    except Exception as exc:
        fail(f"durable VK response fields are invalid: {exc}")
    if expected_payment:
        comparisons["paymentCommitment"] = (
            str(item.get("paymentCommitment", "") or "").lower(),
            expected_payment,
        )
    mismatches = [
        field for field, (actual, expected) in comparisons.items()
        if actual != expected
    ]
    if mismatches:
        fail(
            "durable VK response no longer matches the authorized transfer: "
            + ", ".join(mismatches)
        )

    receipt = item.get("privateReceipt")
    if not isinstance(receipt, dict) or not receipt:
        fail("durable VK response has no required private receipt")
    receipt_mismatches: list[str] = []
    try:
        if int(receipt.get("pieceSize", -1)) != int(expected_size):
            receipt_mismatches.append("pieceSize")
        if int(receipt.get("serviceEnd", -1)) != int(job.get("serviceEnd", service_end) or 0):
            receipt_mismatches.append("serviceEnd")
    except Exception as exc:
        fail(f"durable VK receipt fields are invalid: {exc}")
    receipt_nonce = str(receipt.get("commitmentNonce", "") or "").lower()
    if receipt_nonce and receipt_nonce != expected_nonce:
        receipt_mismatches.append("commitmentNonce")
    receipt_payment = str(receipt.get("paymentCommitment", "") or "").lower()
    if expected_payment and receipt_payment != expected_payment:
        receipt_mismatches.append("paymentCommitment")
    if receipt_mismatches:
        fail(
            "durable VK receipt no longer matches the accepted store terms: "
            + ", ".join(receipt_mismatches)
        )

    vk_candidates = [
        str(quote_info.get("vkAddress", "") or ""),
        str(item.get("expectedVkAddress", "") or ""),
        _resolve_vk_address(peer, vk_expected_address),
    ]
    normalized_vks: list[str] = []
    try:
        for candidate in vk_candidates:
            if candidate:
                normalized_vks.append(HX.prefixed_hex(
                    candidate,
                    expected_bytes=20,
                    field="expected VK address",
                ).lower())
    except ValueError as exc:
        fail(f"durable VK address binding is invalid: {exc}")
    if not normalized_vks:
        fail(
            "durable VK response cannot be bound to the obligated peer's "
            "registered address"
        )
    if len(set(normalized_vks)) != 1:
        fail("durable VK response contains conflicting VK address bindings")
    expected_vk = normalized_vks[0]
    receipt_ok, receipt_reason = CH.verify_vk_receipt(
        receipt,
        expected_piece_root=expected_root,
        expected_vk_address=expected_vk,
        chain_id=int(chain_id),
        storage_proof_contract=storage_proof_contract,
    )
    if not receipt_ok:
        fail(f"VK private receipt verification failed: {receipt_reason}")

    receipt_commitment = str(receipt.get("commitmentHash", "") or "")
    commitment_ok, commitment_reason = verify_commitment_hash(
        expected_root, expected_nonce, receipt_commitment
    )
    if not commitment_ok:
        fail(commitment_reason)
    receipt_delete_hash = str(receipt.get("deletionAuthHash", "") or "").lower()
    if not receipt_delete_hash:
        fail("VK receipt is missing the required deletionAuthHash")
    if receipt_delete_hash != expected_delete_hash:
        fail("VK receipt deletionAuthHash mismatch")

    receipt_tx = str(receipt.get("registrationTxHash", "") or "")
    stored_tx = str(item.get("registrationTxHash", "") or "")
    if stored_tx and receipt_tx and stored_tx.lower() != receipt_tx.lower():
        fail("VK receipt registrationTxHash mismatch")
    item["registrationTxHash"] = receipt_tx or stored_tx
    item["receiptCommitmentHash"] = receipt_commitment
    item["receiptVerified"] = True
    item["commitmentHashVerified"] = True
    item["deletionAuthHashRegistered"] = True
    saved_path = CH.save_vk_receipt(
        receipt,
        commitment_hash=expected_commitment,
    )
    L.log(
        "[receipt] durable VK response cryptographically re-verified  "
        f"receipt={saved_path}"
    )


def vaultmesh_store_piece(
    file_path: str,
    peer: str,
    file_id_hex: str,
    piece_index: int,
    service_end: int = 0,
    vk_expected_address: str = "",
    chain_id: int = 0,
    storage_proof_contract: str = "",
    file_format: str = "",
    predeposited_escrow: dict | None = None,
    upload_instance_id: str = "",
    file_registration_contract: str = "",
) -> dict:
    file_id_hex = HX.normalize_file_id(file_id_hex)
    upload_instance_id = str(upload_instance_id or "").strip().lower()
    if not upload_instance_id:
        raise RuntimeError("uploadInstanceId is required for durable storage")
    if not chain_id:
        chain_id = int(C.w3.eth.chain_id)
    if not storage_proof_contract and C.storage_proof_sc is not None:
        storage_proof_contract = str(C.storage_proof_sc.address)
    if not file_registration_contract and C.file_registration_sc is not None:
        file_registration_contract = str(C.file_registration_sc.address)
    if not storage_proof_contract:
        raise RuntimeError("StorageProofSC is required for verified storage")
    if not file_registration_contract:
        raise RuntimeError("FileRegistrationSC is required for verified storage")
    chain_namespace = {
        "chainId": int(chain_id),
        "fileRegistrationContract": str(file_registration_contract).lower(),
    }
    PJ.ensure_recovered(C.BASE_DIR)
    logical_job = XFER.get_or_create_logical_piece_job(
        C.BASE_DIR, file_path, file_id_hex, piece_index,
        int(service_end or 0), file_format,
        upload_instance_id=upload_instance_id,
        chain_namespace=chain_namespace,
    )
    if logical_job.get("status") == "completed" and isinstance(logical_job.get("result"), dict):
        result = dict(logical_job["result"])
        verified, reason = confirm_registration_finality(result)
        PJ.record_registration(
            C.BASE_DIR, result, source="completed-logical-job-recheck"
        )
        if not verified:
            queue_storage_verification(result)
            raise XFER.TransferPending(
                "completed logical storage is awaiting authoritative re-verification: "
                + reason
            )
        winning_peer = peer_id_from_peer(
            str(result.get("resolvedMultiaddr") or result.get("peerId") or "")
        )
        requested_peer = peer_id_from_peer(peer)
        if winning_peer and requested_peer and winning_peer != requested_peer:
            raise XFER.TransferPending(
                f"logical piece {piece_index} is already registered on a "
                "different VK and requires assignment reconciliation"
            )
        PJ.record_registration(
            C.BASE_DIR, result, source="completed-logical-job-resume"
        )
        XFER.reconcile_peer_jobs_from_completed_logical(
            C.BASE_DIR,
            logical_job,
            result,
        )
        return result
    job = XFER.get_or_create_upload_job(
        C.BASE_DIR, file_path, peer, file_id_hex, piece_index,
        int(service_end or 0), file_format,
        upload_instance_id=upload_instance_id,
        chain_namespace=chain_namespace,
    )
    if str(job.get("status", "")) == "blocked_security":
        raise XFER.TransferSecurityBlocked(
            "durable VK response is security-blocked: "
            + str(
                job.get("securityVerificationError")
                or "stored response failed a trust check"
            )
        )

    # Once the VK response is durably bound to this exact job pair, recovery
    # is chain-only.  Do not reconnect or resend bytes merely because the
    # original response arrived before its registration/proof became final.
    pending_result = job.get("pendingVerificationResult")
    if not isinstance(pending_result, dict):
        pending_result = logical_job.get("pendingVerificationResult")
    if isinstance(pending_result, dict):
        result = dict(pending_result)
        _reverify_durable_store_response(
            result,
            logical_job,
            job,
            file_path=file_path,
            peer=str(job.get("peer") or peer),
            file_id_hex=file_id_hex,
            piece_index=piece_index,
            service_end=int(job.get("serviceEnd", service_end) or 0),
            vk_expected_address=vk_expected_address,
            chain_id=chain_id,
            storage_proof_contract=storage_proof_contract,
            file_registration_contract=file_registration_contract,
        )
        verified, reason = confirm_registration_finality(result)
        PJ.record_registration(
            C.BASE_DIR,
            result,
            source="pending-verification-job-recheck",
        )
        if not verified:
            queue_storage_verification(result)
            raise XFER.TransferPending(
                "VK already stored this piece; authoritative chain "
                "verification is pending: " + reason
            )
        if result.get("escrowPendingFinalize"):
            try:
                _finalize_escrow_if_needed(result)
            except Exception as exc:
                result["escrowFinalizeError"] = str(exc)
                PJ.record_registration(
                    C.BASE_DIR,
                    result,
                    source="pending-verification-escrow-finalize",
                )
                queue_storage_verification(result)
                raise XFER.TransferPending(
                    "storage is verified but escrow finalization is pending: "
                    + str(exc)
                ) from exc
        XFER.complete_verified_piece_jobs(C.BASE_DIR, result)
        return result
    if XFER.uploads_paused():
        XFER.update_upload_job(C.BASE_DIR, job, status="paused")
        raise XFER.TransferPaused("upload paused before quote or escrow admission")
    if job.get("status") == "completed" and isinstance(job.get("result"), dict):
        result = dict(job["result"])
        verified, reason = confirm_registration_finality(result)
        PJ.record_registration(
            C.BASE_DIR, result, source="completed-peer-job-recheck"
        )
        if not verified:
            queue_storage_verification(result)
            raise XFER.TransferPending(
                "completed peer storage is awaiting authoritative re-verification: "
                + reason
            )
        XFER.complete_verified_piece_jobs(C.BASE_DIR, result)
        return result

    # The first durable job fixes the service term. UI retries naturally
    # recompute "now + days", but resume must not create a new obligation.
    service_end = int(job.get("serviceEnd", service_end) or 0)

    commitment_nonce = str(job["commitmentNonce"])
    deletion_auth_secret = str(job["deletionAuthSecret"])
    deletion_auth_hash = compute_deletion_auth_hash(deletion_auth_secret)

    # ── Pre-store: get quote from VK then deposit escrow ──────────────────────
    # DO deposits FIRST so VK can verify on-chain before accepting the file.
    # If VKEscrow is not configured, or VK doesn't support quotes, this is a
    # no-op and the store proceeds as before (no paymentCommitment in request).
    expected_piece_root, expected_piece_hash, expected_block_count, file_size = (
        compute_piece_commitment(file_path, _PIECE_MERKLE_BLOCK_SIZE)
    )
    item_escrow: dict = dict(job.get("escrow") or {})
    payment_commitment = ""
    quote_refusal: dict = {}
    quote_info = job.get("quoteInfo") if isinstance(job.get("quoteInfo"), dict) else None
    if predeposited_escrow:
        item_escrow.update(predeposited_escrow)
        payment_commitment = str(predeposited_escrow.get("paymentCommitment", "") or "")
        XFER.update_upload_job(C.BASE_DIR, job, escrow=item_escrow)
    else:
        payment_commitment = str(item_escrow.get("paymentCommitment", "") or "")
        if not quote_info:
            quote_info = job.get("quoteInfo") if isinstance(job.get("quoteInfo"), dict) else None
        if not payment_commitment:
            check_vk_admission_for_new_store(peer, file_size, vk_expected_address)
        if not payment_commitment and not quote_info:
            quote = _get_quote(
                peer, file_size, int(service_end or 0), str(job["transferId"]),
                refusal=quote_refusal,
                file_id=file_id_hex,
                vk_address=vk_expected_address,
            )
            if quote:
                quote_info = _prepare_escrow_quote(
                    quote,
                    file_size,
                    int(service_end or 0),
                    peer,
                    item_escrow,
                    vk_expected_address,
                )
                if quote_info:
                    # Persist quote commitments before sending an escrow tx. A
                    # crash after mining can then recover the same deposit.
                    XFER.update_upload_job(
                        C.BASE_DIR, job, quoteInfo=quote_info, escrow=item_escrow,
                    )
        if not payment_commitment and quote_info:
            if XFER.uploads_paused():
                XFER.update_upload_job(C.BASE_DIR, job, status="paused")
                raise XFER.TransferPaused("upload paused before escrow deposit")
            payment_commitment = _deposit_escrow_from_quote_info(item_escrow, quote_info)
            XFER.update_upload_job(C.BASE_DIR, job, escrow=item_escrow)
            if not payment_commitment:
                raise XFER.TransferPending(
                    "escrow deposit is not confirmed; resume this durable transfer"
                )
        if C.vk_escrow is not None and int(service_end or 0) > 0 and not payment_commitment:
            # Carry the keeper's own words. "Busy, try later" and "full, and it
            # will stay full" both land here, and only the reason separates them.
            refusal_reason = str(quote_refusal.get("reason", "") or "")
            # TransferPending means "resume this transfer as it stands", and for a
            # refusal that is final for this transferId that instruction can never
            # succeed: the keeper's reservation for this id has already settled
            # without delivering anything. Raising a plain failure instead lets the
            # caller cancel pre-obligation, which retires the spent id so the next
            # attempt can ask a question a keeper is still able to answer.
            if quote_refusal_retires_transfer_id(quote_refusal):
                raise RuntimeError(
                    "this transfer's durable quote is spent and cannot take a new "
                    "escrow deposit; a fresh transfer is required"
                    + (f": {refusal_reason}" if refusal_reason else "")
                )
            raise XFER.TransferPending(
                "VK escrow is configured but no durable payment commitment is available"
                + (f": {refusal_reason}" if refusal_reason else "")
            )

    uploader, transfer_issued_at, transfer_sig = build_vaultmesh_store_auth(
        str(job["transferId"]), file_path, file_id_hex, piece_index, file_size,
        int(service_end or 0), commitment_nonce, payment_commitment,
        deletion_auth_hash, file_format,
        expected_piece_root=expected_piece_root,
        piece_block_size=_PIECE_MERKLE_BLOCK_SIZE,
    )

    cmd = [
        C.VAULTMESH_CMD,
        "--mode", "store",
        "--peer", peer,
        "--file", file_path,
        "--file-id", file_id_hex,
        "--piece-index", str(int(piece_index)),
        "--commitment-nonce", commitment_nonce,
        "--deletion-auth-hash", deletion_auth_hash,
        "--transfer-id", str(job["transferId"]),
        "--uploader", uploader,
        "--transfer-issued-at", str(transfer_issued_at),
        "--transfer-sig", transfer_sig,
        "--expected-piece-root", expected_piece_root,
        "--expected-piece-block-size", str(_PIECE_MERKLE_BLOCK_SIZE),
    ]
    if int(service_end or 0) > 0:
        cmd.extend(["--service-end", str(int(service_end))])
    if payment_commitment:
        cmd.extend(["--payment-commitment", payment_commitment])
    if file_format:
        cmd.extend(["--file-format", file_format])

    if job.get("status") == "response_received" and job.get("rawStoreResponse"):
        out = str(job["rawStoreResponse"])
    else:
        out = XFER.run_upload_process(C.BASE_DIR, job, cmd)
    resp = json.loads(out)

    if not resp.get("ok"):
        _record_admission_failure_candidate(
            job, peer, vk_expected_address, payment_commitment,
            str(resp.get("err", "VaultMesh store failed")),
            quote_info if isinstance(quote_info, dict) else None,
            str(resp.get("admissionFailureSignature", "") or ""),
        )
        raise RuntimeError(resp.get("err", "VaultMesh store failed"))

    piece_root = resp.get("pieceRoot") or resp.get("pieceId") or resp.get("cid")
    if not piece_root:
        raise RuntimeError("VaultMesh response missing pieceRoot")
    try:
        piece_root = HX.prefixed_hex(
            piece_root, expected_bytes=32, field="VK response pieceRoot"
        )
    except ValueError as exc:
        raise RuntimeError(f"VaultMesh response has invalid pieceRoot: {exc}") from exc
    response_size = int(resp.get("size", -1) or 0)
    response_block_size = int(resp.get("pieceBlockSize", 0) or 0)
    response_block_count = int(resp.get("pieceBlockCount", -1) or 0)
    response_piece_hash = str(resp.get("pieceHash", "") or "").lower()
    response_root_alg = str(resp.get("rootAlg", "") or "")
    response_hash_alg = str(resp.get("hashAlg", "") or "")
    response_mismatches = []
    if piece_root.lower() != expected_piece_root.lower():
        response_mismatches.append("pieceRoot")
    if response_size != int(file_size):
        response_mismatches.append("size")
    if response_block_size != _PIECE_MERKLE_BLOCK_SIZE:
        response_mismatches.append("pieceBlockSize")
    if response_block_count != expected_block_count:
        response_mismatches.append("pieceBlockCount")
    if response_piece_hash != expected_piece_hash.lower():
        response_mismatches.append("pieceHash")
    if response_root_alg != "merkle-sha256-v1":
        response_mismatches.append("rootAlg")
    if response_hash_alg != "sha2-256":
        response_mismatches.append("hashAlg")

    stable_peer_id = peer_id_from_peer(peer)
    durable_vk_address = str(
        (quote_info or {}).get("vkAddress", "")
        if isinstance(quote_info, dict)
        else ""
    ) or _resolve_vk_address(peer, vk_expected_address)
    if durable_vk_address:
        try:
            durable_vk_address = HX.prefixed_hex(
                durable_vk_address,
                expected_bytes=20,
                field="expected VK address",
            )
        except ValueError as exc:
            raise RuntimeError(f"invalid expected VK address: {exc}") from exc
    item = {
        "name": os.path.basename(file_path),
        "path": file_path,
        "fileId": file_id_hex,
        "uploadInstanceId": upload_instance_id,
        "chainId": int(chain_id),
        "fileRegistrationContract": str(file_registration_contract),
        "pieceIndex": int(piece_index),
        # The locally computed root is the storage identity authorized by the
        # DO.  Keep any different VK response only as evidence; never let an
        # untrusted response choose the durable commitment identity.
        "pieceRoot": expected_piece_root,
        "expectedPieceRoot": expected_piece_root,
        "responsePieceRoot": piece_root,
        "peerId": stable_peer_id,
        "vkPeer": stable_peer_id,
        "resolvedMultiaddr": peer,
        "expectedVkAddress": durable_vk_address,
        "size": response_size,
        "hashAlg": resp.get("hashAlg", "sha2-256"),
        "rootAlg": resp.get("rootAlg", "merkle-sha256-v1"),
        "pieceHash": resp.get("pieceHash", ""),
        "pieceBlockSize": int(resp.get("pieceBlockSize", 0) or 0),
        "pieceBlockCount": int(resp.get("pieceBlockCount", 0) or 0),
        "sectorId": resp.get("sectorId", ""),
        "sectorRoot": resp.get("sectorRoot", ""),
        "sectorExpiration": int(resp.get("sectorExpiration", 0) or 0),
        "piecePosition": int(resp.get("piecePosition", 0) or 0),
        "inclusionProof": resp.get("inclusionProof", []) or [],
        "storedAt": resp.get("storedAt", ""),
        "serviceEnd": int(service_end or 0),
        "commitmentNonce": commitment_nonce,
        "deletionAuthSecret": deletion_auth_secret,
        "deletionAuthHash": deletion_auth_hash,
        "fileFormat": resp.get("fileFormat", file_format),
        "transferId": str(job["transferId"]),
        "peerJobId": str(job["jobId"]),
        "logicalJobId": str(logical_job["logicalJobId"]),
        "sourceDigest": str(logical_job["fileDigest"]),
        "storedOnVK": True,
        "storageLifecycleState": "stored",
        "commitmentHash": compute_commitment_hash(
            expected_piece_root,
            commitment_nonce,
        ),
        "registrationLifecycleStatus": "response_received_unverified",
    }
    # Merge pre-store escrow deposit results (escrowDepositTx, escrowDepositWei, etc.)
    item.update(item_escrow)
    # The deployment that stores this piece: its disputes go there, even after a V2 update.
    item["vkEscrowContract"] = str(
        (job.get("quoteInfo") or {}).get("vkEscrowContract", "")
        or (C.vk_escrow.address if C.vk_escrow is not None else "")
    )

    receipt = resp.get("privateReceipt")
    if isinstance(receipt, dict):
        item["privateReceipt"] = receipt
        item["registrationTxHash"] = str(
            receipt.get("registrationTxHash", "") or ""
        )

    # The expected commitment is computed from DO-held material, not trusted
    # response fields. Persist it before every receipt/event validation so a
    # malicious response, process stop, or verification exception cannot turn
    # already received bytes into an invisible orphan.
    PJ.record_registration(
        C.BASE_DIR,
        item,
        source="vaultmesh-store-response-unverified",
    )
    # Bind the logical and peer jobs to this exact response before any trust
    # checks. A crash or rejected receipt can no longer leave bytes/escrow
    # detached from the durable job pair, and completion remains impossible
    # until the reconciler proves every condition below.
    XFER.mark_piece_jobs_pending_verification(
        C.BASE_DIR, logical_job, job, item,
    )
    if response_mismatches:
        reason = (
            "VK store response does not match the locally committed piece: "
            + ", ".join(response_mismatches)
        )
        _block_store_security_verification(item, job, reason)
        raise RuntimeError(reason)

    if receipt:
        L.log("[receipt] VK private receipt received")
        if not durable_vk_address:
            reason = (
                "VK receipt cannot be bound to the selected peer's registered address"
            )
            _block_store_security_verification(item, job, reason)
            raise RuntimeError(reason)
        receipt_mismatches = []
        if int(receipt.get("pieceSize", -1) or 0) != int(file_size):
            receipt_mismatches.append("pieceSize")
        if int(receipt.get("serviceEnd", -1) or 0) != int(service_end or 0):
            receipt_mismatches.append("serviceEnd")
        receipt_nonce = str(receipt.get("commitmentNonce", "") or "").lower()
        if receipt_nonce and receipt_nonce != commitment_nonce.lower():
            receipt_mismatches.append("commitmentNonce")
        receipt_payment = str(receipt.get("paymentCommitment", "") or "").lower()
        if payment_commitment and receipt_payment != payment_commitment.lower():
            receipt_mismatches.append("paymentCommitment")
        if receipt_mismatches:
            reason = (
                "VK private receipt does not match the accepted store terms: "
                + ", ".join(receipt_mismatches)
            )
            _block_store_security_verification(item, job, reason)
            raise RuntimeError(reason)
        ok, reason = CH.verify_vk_receipt(
            receipt,
            expected_piece_root=piece_root,
            expected_vk_address=durable_vk_address,
            chain_id=chain_id,
            storage_proof_contract=storage_proof_contract,
        )
        if ok:
            L.log("[receipt] VK signature and storage terms verified")
        else:
            L.log(f"[receipt] VERIFICATION FAILED: {reason}")
        item["receiptVerified"] = ok
        if not ok:
            _block_store_security_verification(item, job, reason)
            raise RuntimeError(f"VK private receipt verification failed: {reason}")

        receipt_commitment_hash = receipt.get("commitmentHash", "")
        receipt_reg_tx = receipt.get("registrationTxHash", "")
        receipt_deletion_auth_hash = str(receipt.get("deletionAuthHash", "") or "")
        if not receipt_deletion_auth_hash:
            _block_store_security_verification(
                item,
                job,
                "VK receipt is missing the required deletionAuthHash",
            )
            raise RuntimeError(
                "VK receipt is missing the required deletionAuthHash"
            )
        item["deletionAuthHashRegistered"] = (
            receipt_deletion_auth_hash.lower() == deletion_auth_hash.lower()
        )
        if not item["deletionAuthHashRegistered"]:
            _block_store_security_verification(
                item,
                job,
                "VK receipt deletionAuthHash mismatch",
            )
            raise RuntimeError("VK receipt deletionAuthHash mismatch")
        if receipt_commitment_hash:
            ch_ok, ch_reason = verify_commitment_hash(
                piece_root, commitment_nonce, receipt_commitment_hash
            )
            if ch_ok:
                L.log(
                    f"[file_reg] commitmentHash verified locally  "
                    f"hash={receipt_commitment_hash[:18]}..."
                )
            else:
                L.log(f"[file_reg] commitmentHash MISMATCH: {ch_reason}")
                _block_store_security_verification(item, job, ch_reason)
                raise RuntimeError(ch_reason)
            # Keep the locally computed commitment as the authoritative field;
            # the signed receipt value has just been proven equal.
            item["receiptCommitmentHash"] = receipt_commitment_hash
            item["commitmentHashVerified"] = ch_ok

            saved_path = CH.save_vk_receipt(
                receipt,
                commitment_hash=item["commitmentHash"],
            )
            L.log(f"[receipt] protected receipt saved to: {saved_path}")

            item["registrationTxHash"] = receipt_reg_tx
            if receipt_reg_tx:
                L.log(f"[file_reg] registrationTxHash={receipt_reg_tx[:18]}...")
                ev_ok, ev_reason = verify_registration_tx_event(receipt_reg_tx, receipt)
                if ev_ok:
                    item["fileRegTxEventVerified"] = True
                    L.log(f"[file_reg] tx event verified  {ev_reason}")
                elif "pending" in ev_reason:
                    item["fileRegTxEventVerified"] = None
                    L.log(
                        f"[file_reg] tx event check deferred (tx pending) — "
                        f"call confirm_registration_finality(item) after mining"
                    )
                else:
                    L.log(f"[dispute] VK registered different data on-chain — submitting dispute")
                    _block_store_security_verification(item, job, ev_reason)
                    _dispute_and_settle(job, receipt, commitment_nonce, quote_info, payment_commitment)
                    raise RuntimeError(
                        f"FileStorageRegistered event mismatch in tx "
                        f"{receipt_reg_tx[:18]}...: {ev_reason}"
                    )

            reg_ok, reg_reason = verify_file_registration_onchain(
                receipt_commitment_hash, receipt
            )
            if reg_ok:
                L.log(f"[file_reg] on-chain record verified  commitmentHash={receipt_commitment_hash[:18]}...")
            else:
                if not receipt_reg_tx:
                    L.log(f"[dispute] VK gave receipt but never registered on-chain — submitting dispute")
                    _block_store_security_verification(item, job, reg_reason)
                    _dispute_and_settle(job, receipt, commitment_nonce, quote_info, payment_commitment)
                    raise RuntimeError(
                        f"file registration not found on-chain and no tx was submitted "
                        f"(commitmentHash={receipt_commitment_hash[:18]}...): {reg_reason}"
                    )
                L.log(f"[file_reg] on-chain record not yet visible (tx pending): {reg_reason}")
            item["fileRegOnChainVerified"] = reg_ok
            item["registrationLifecycleStatus"] = (
                "onchain_confirmed" if reg_ok else "onchain_pending"
            )
            final_ok, final_reason = confirm_registration_finality(item)
            if final_ok:
                L.log(f"[file_reg] fully verified  commitmentHash={receipt_commitment_hash[:18]}...")
            else:
                L.log(f"[file_reg] verification pending: {final_reason}")
        else:
            reason = "VK private receipt has no commitmentHash"
            L.log(f"[file_reg] {reason}")
            _block_store_security_verification(item, job, reason)
            raise RuntimeError(reason)
    else:
        reason = "VK response has no required private receipt"
        L.log(f"[receipt] {reason}")
        _block_store_security_verification(item, job, reason)
        raise RuntimeError(reason)

    if item.get("escrowPendingFinalize"):
        if item.get("fileRegFullyVerified"):
            try:
                _finalize_escrow_if_needed(item)
            except Exception as exc:
                item["escrowFinalizeError"] = str(exc)
                item["storageVerificationStatus"] = "pending"
                item["storageVerificationReason"] = "escrow finalization pending: " + str(exc)
        else:
            L.log("[escrow] finalization deferred until storage registration is fully verified")

    # This transaction is deliberately before every completion marker.  Once a
    # VK response can represent a storage obligation, no sibling failure,
    # process crash, or next upload may make the piece disappear locally.
    PJ.record_registration(C.BASE_DIR, item, source="vaultmesh-store-response")
    # Refresh the crash-safe checkpoint with verification progress. Immutable
    # receipt/transfer evidence is checked by the transfer manager; only the
    # explicit verification fields are allowed to advance.
    XFER.mark_piece_jobs_pending_verification(
        C.BASE_DIR, logical_job, job, item,
    )

    if not item.get("fileRegFullyVerified"):
        item.setdefault("storageVerificationStatus", "pending")
        queue_storage_verification(item)
        raise XFER.TransferPending(
            "VK stored the piece, but its on-chain registration/proof is not "
            "fully verified; the same durable transfer will be reconciled"
        )

    # Only fully verified storage is a completed logical result. The journal
    # was committed first, so a crash at either following write is repaired by
    # the verification reconciler without selecting another VK.
    XFER.complete_verified_piece_jobs(C.BASE_DIR, item)
    return item


def _dispute_and_settle(
    job: dict,
    receipt: dict,
    commitment_nonce: str,
    quote_info: dict | None,
    payment_commitment: str,
) -> None:
    """File the storage dispute of a failed store, then settle its escrow if it is valid."""
    disputed, reason = CH.submit_storage_dispute(
        receipt, commitment_nonce, escrow_address=str((quote_info or {}).get("vkEscrowContract", "") or "")
    )
    if disputed:
        _settle_storage_dispute_escrow(job, receipt, quote_info, payment_commitment)
    else:
        L.log(f"[dispute] storage dispute not filed: {reason}")


def _settle_storage_dispute_escrow(
    job: dict, receipt: dict, quote_info: dict | None, payment_commitment: str,
) -> bool:
    """Refund the escrow of a storage dispute just filed, if the chain found it valid.

    A valid dispute moves no escrow (Phase 1D): the owner settles it with the quote's
    link nonce. What the settlement needs is kept in the upload job, so the escrow
    reconciler tries again when this attempt does not go through.
    """
    quote = quote_info if isinstance(quote_info, dict) else {}
    record = {
        "receipt": {
            key: str(receipt.get(key, "") or "")
            for key in ("vkAddress", "receiptNonce", "pieceRoot")
        },
        "paymentCommitment": str(payment_commitment or quote.get("paymentCommitment", "") or ""),
        "registrationCommitment": str(quote.get("registrationCommitment", "") or ""),
        "linkNonce": str(quote.get("linkNonce", "") or ""),
        "vkEscrowContract": str(quote.get("vkEscrowContract", "") or ""),
    }
    return _settle_disputed_escrow_record(job, record)


def _settle_disputed_escrow_record(job: dict, record: dict) -> bool:
    settled, result = CH.settle_disputed_escrow(
        record["receipt"],
        record["paymentCommitment"],
        record["registrationCommitment"],
        record["linkNonce"],
        escrow_address=str(record.get("vkEscrowContract", "") or ""),
    )
    record = dict(
        record,
        settled=bool(settled),
        result=str(result),
        closed=bool(settled) or str(result).startswith(CH.SETTLEMENT_FINAL),
    )
    XFER.update_upload_job(C.BASE_DIR, job, disputedEscrow=record)
    if not settled:
        L.log(f"[dispute] disputed escrow not settled: {result}")
    return bool(settled)


def reconcile_escrows() -> None:
    """Look again at every escrow this owner paid: settle it, take it back, or leave it.

    A valid storage dispute whose escrow is not settled yet is settled first. An
    escrow no keeper claimed is taken back once its service end and the reclaim
    grace are over; VKEscrow decides, so one it would refuse (renewed, claimed,
    refunded, never finalized) costs no transaction. An escrow claimed or refunded
    is closed and not looked at again.
    """
    if C.vk_escrow is None:
        return
    grace = int(C.vk_escrow.functions.reclaimGraceSeconds().call())
    now = latest_chain_timestamp()
    for job in XFER.jobs_with_escrow(C.BASE_DIR):
        disputed = job.get("disputedEscrow")
        if isinstance(disputed, dict) and not disputed.get("closed"):
            _settle_disputed_escrow_record(job, disputed)
            continue
        escrow = dict(job.get("escrow") or {})
        quote = job.get("quoteInfo") if isinstance(job.get("quoteInfo"), dict) else {}
        service_end = int(quote.get("serviceEnd", 0) or job.get("serviceEnd", 0) or 0)
        if escrow.get("reclaimTx") or escrow.get("closed"):
            continue
        if service_end <= 0 or now < service_end + grace:
            continue
        reclaimed, result = CH.reclaim_escrow(
            str(escrow["paymentCommitment"]), str(quote.get("vkEscrowContract", "") or ""),
        )
        if reclaimed:
            escrow["reclaimTx"] = result
        elif "already claimed or refunded" in result:
            escrow["closed"] = True
        else:
            continue
        XFER.update_upload_job(C.BASE_DIR, job, escrow=escrow)


_escrow_reconciler_lock = threading.Lock()
_escrow_reconciler_started = False


def start_escrow_reconciler(interval_seconds: int = 600) -> None:
    global _escrow_reconciler_started
    with _escrow_reconciler_lock:
        if _escrow_reconciler_started:
            return
        _escrow_reconciler_started = True

    def _loop() -> None:
        try:
            from . import do_release_checks as RC
            RC.run_checks()  # at start: may new escrows begin with this release and network?
        except Exception as exc:
            L.log(f"[release] start-up release checks failed to run: {exc}")
        while True:
            try:
                reconcile_escrows()
            except Exception as exc:
                L.log(f"[escrow] escrow reconciler error: {exc}")
            time.sleep(interval_seconds)

    threading.Thread(target=_loop, name="escrow-reconciler", daemon=True).start()


_ADMISSION_FAILURE_LOG = Path(C.BASE_DIR) / "admission_failures.jsonl"


def _record_admission_failure_candidate(
    job: dict,
    peer: str,
    vk_expected_address: str,
    payment_commitment: str,
    store_error: str,
    quote_info: dict | None = None,
    failure_signature: str = "",
) -> None:
    if not payment_commitment:
        return
    err = str(store_error or "").lower()
    if not any(marker in err for marker in (
        "insufficient unreserved capacity",
        "insufficient proved capacity",
        "admission margin would be violated",
        "admission closed",
    )):
        return
    vk_address = _resolve_vk_address(peer, vk_expected_address)
    registration_commitment = str((quote_info or {}).get("registrationCommitment", "") or "")
    quoted_price_wei = int((quote_info or {}).get("priceWei", 0) or 0)
    quote_valid_until = int((quote_info or {}).get("quoteValidUntil", 0) or 0)
    quote_signature = str((quote_info or {}).get("vkSignature", "") or "")
    link_nonce = str((quote_info or {}).get("linkNonce", "") or "")
    record = {
        "recordedAt": datetime.datetime.utcnow().isoformat() + "Z",
        "transferId": str(job.get("transferId", "")),
        "peer": peer,
        "vkAddress": vk_address,
        "paymentCommitment": payment_commitment,
        "registrationCommitment": registration_commitment,
        "quotedPriceWei": quoted_price_wei,
        "quoteValidUntil": quote_valid_until,
        "quoteSignature": quote_signature,
        "failureSignature": failure_signature,
        "linkNonce": link_nonce,
        "vkEscrowContract": str((quote_info or {}).get("vkEscrowContract", "") or ""),
        "storeError": store_error,
        "doAddress": getattr(C.config, "DO_ADDRESS", ""),
    }
    # The DO is the authoritative escrow depositor and can submit immediately.
    # Persist a Reporter candidate only when direct submission cannot be confirmed.
    try:
        submitted, result = CH.submit_admission_failure_dispute(
            vk_address,
            payment_commitment,
            registration_commitment,
            quoted_price_wei,
            quote_valid_until,
            quote_signature,
            failure_signature,
            link_nonce=link_nonce,
            escrow_address=record["vkEscrowContract"],
        )
        record["directDisputeSubmitted"] = bool(submitted)
        record["directDisputeResult"] = str(result or "")
    except Exception as exc:
        record["directDisputeSubmitted"] = False
        record["directDisputeResult"] = str(exc)
    try:
        _ADMISSION_FAILURE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _ADMISSION_FAILURE_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except Exception as exc:
        L.log(f"[admission] failed to record admission failure candidate: {exc}")


def retry_unsent_admission_disputes() -> int:
    """Send again the admission complaints that never reached the chain.

    A keeper signs a quote saying it has room, is paid, and then refuses the
    piece. That is worth money, and this owner is the one who may claim it:
    the contract takes the complaint from whoever paid, which is us.

    It is sent the moment the refusal happens. When that send fails -- the RPC
    unreachable, no gas, the machine going down mid-call -- the line is still
    written to admission_failures.jsonl, and until now nothing ever looked at
    it again. One bad minute and the claim was simply lost.

    So the file is read at startup and every line still marked unsent is tried
    once more. Nothing here is new evidence: the signed quote and the signed
    refusal were kept in the line when it was written, which is the whole
    reason the line exists.

    Sending twice is safe. The contract keys a complaint by keeper and payment
    commitment and answers "already filed" for the second one, so a line that
    did reach the chain and was wrongly marked unsent costs one transaction,
    not a wrong result.

    Returns how many were sent this time.
    """
    path = _ADMISSION_FAILURE_LOG
    if not path.is_file():
        return 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        L.log(f"[admission] could not read {path.name}: {exc}")
        return 0

    rows: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue  # a half-written line from a crash: skip it, keep the rest
        if isinstance(row, dict):
            rows.append(row)

    pending = [r for r in rows if not r.get("directDisputeSubmitted")]
    if not pending:
        return 0

    L.log(f"[admission] {len(pending)} complaint(s) never reached the chain; trying again")
    sent = 0
    for row in pending:
        vk_address = str(row.get("vkAddress", "") or "")
        payment_commitment = str(row.get("paymentCommitment", "") or "")
        if not vk_address or not payment_commitment:
            continue
        try:
            submitted, result = CH.submit_admission_failure_dispute(
                vk_address,
                payment_commitment,
                str(row.get("registrationCommitment", "") or ""),
                int(row.get("quotedPriceWei", 0) or 0),
                int(row.get("quoteValidUntil", 0) or 0),
                str(row.get("quoteSignature", "") or ""),
                str(row.get("failureSignature", "") or ""),
                link_nonce=str(row.get("linkNonce", "") or ""),
                escrow_address=str(row.get("vkEscrowContract", "") or ""),
            )
        except Exception as exc:
            submitted, result = False, str(exc)
        row["directDisputeSubmitted"] = bool(submitted)
        row["directDisputeResult"] = str(result or "")
        if submitted:
            row["retriedAt"] = datetime.datetime.utcnow().isoformat() + "Z"
            sent += 1
            L.log(f"[admission] sent for keeper {vk_address[:10]}")
        else:
            L.log(f"[admission] still cannot send for keeper {vk_address[:10]}: {result}")

    # Rewrite the whole file with what is now true. A line that went through
    # must not be tried a third time, and one that did not must stay in the
    # list -- which is why this is written even when nothing was sent.
    try:
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        temporary.replace(path)
    except OSError as exc:
        L.log(f"[admission] could not update {path.name}: {exc}")

    return sent


def _resolve_vk_address(peer: str, vk_expected_address: str = "") -> str:
    expected = str(vk_expected_address or "").strip()
    if expected:
        return expected
    peer_key = str(peer or "").strip()
    peer_id = peer_id_from_peer(peer_key)
    matches: set[str] = set()
    for row in (getattr(S, "vault_keeper_rows", None) or {}).values():
        row_peer = str(row.get("multiaddr", "")).strip()
        if row_peer == peer_key or (
            peer_id and peer_id_from_peer(row_peer) == peer_id
        ):
            address = str(row.get("address", "")).strip()
            if address:
                matches.add(address.lower())
    if len(matches) == 1:
        return next(iter(matches))
    return ""


def is_admission_capacity_error(message: str) -> bool:
    """True when an error means selected VKs have no room for new stores."""
    lower = str(message or "").lower()
    markers = (
        "admission closed",
        "admission margin",
        "admission free",
        "admission margin would be violated",
        "no admission space",
        "insufficient unreserved capacity",
        "insufficient proved capacity",
        "waiting for vk admission",
        "selected vault keepers have no admission space",
    )
    return any(marker in lower for marker in markers)


def verify_selected_vks_admission_for_upload(
    peers: list[str],
    piece_size_bytes: int,
    vk_addresses: list[str] | None = None,
) -> None:
    """Raise RuntimeError when any selected VK cannot admit a new store."""
    if not peers:
        raise RuntimeError("no Vault Keepers selected for upload")
    piece_size = int(piece_size_bytes or 0)
    failures: list[str] = []
    for index, peer in enumerate(peers):
        vk_addr = ""
        if vk_addresses and index < len(vk_addresses):
            vk_addr = str(vk_addresses[index] or "").strip()
        try:
            check_vk_admission_for_new_store(peer, piece_size, vk_addr)
        except XFER.TransferPending as exc:
            failures.append(f"{short_peer(peer)}: {exc}")
        except Exception as exc:
            failures.append(f"{short_peer(peer)}: {exc}")
    if failures:
        raise RuntimeError(
            "selected Vault Keepers have no admission space: " + "; ".join(failures)
        )


def check_vk_admission_for_new_store(peer: str, piece_size: int, vk_expected_address: str = "") -> None:
    """Raise TransferPending when a VK must not accept a new escrow deposit."""
    vk_addr = _resolve_vk_address(peer, vk_expected_address)

    registry_checked = False
    if vk_addr and C.vault_keeper_registry is not None:
        try:
            checksum = C.w3.to_checksum_address(vk_addr)
            if hasattr(C.vault_keeper_registry.functions, "isAdmissionOpen"):
                registry_open = bool(
                    C.vault_keeper_registry.functions.isAdmissionOpen(checksum).call()
                )
                registry_checked = True
                if not registry_open:
                    raise XFER.TransferPending("VK admission closed on VaultKeeperRegistry")
        except XFER.TransferPending:
            raise
        except Exception as exc:
            L.log(f"[admission] registry check unavailable for {vk_addr[:10]}...: {exc}")

    info = get_vk_info(peer)
    if not info:
        source = "registry and VK Info" if not registry_checked else "VK Info"
        raise XFER.TransferPending(f"VK admission unavailable: could not verify {source}")

    if info.get("admissionClosed"):
        reason = str(info.get("admissionReason") or "VK admission closed (local)")
        raise XFER.TransferPending(reason)

    free_bytes = int(info.get("admissionFreeBytes") or info.get("freeBytes") or 0)
    margin_bytes = int(info.get("admissionMarginBytes") or 0)
    allocatable_bytes = free_bytes if free_bytes > margin_bytes else 0
    piece_size = int(piece_size or 0)
    total_capacity = int(info.get("totalCapacityBytes") or 0)
    if total_capacity > 0 and allocatable_bytes <= 0:
        raise XFER.TransferPending(
            f"VK admission closed: free={free_bytes} margin={margin_bytes} allocatable=0"
        )
    if piece_size > 0 and total_capacity > 0:
        if margin_bytes > 0 and free_bytes <= margin_bytes:
            raise XFER.TransferPending(
                f"VK unreserved free bytes {free_bytes} do not exceed admission margin {margin_bytes}"
            )
        if piece_size > free_bytes:
            raise XFER.TransferPending(
                f"piece size {piece_size} exceeds VK unreserved free bytes {free_bytes} "
                f"(free={free_bytes} margin={margin_bytes})"
            )


def get_vk_info(peer: str) -> dict:
    """Call VK InfoProtocol and return capacity stats dict. Returns empty dict on failure."""
    try:
        cmd = [C.VAULTMESH_CMD, "--mode", "info", "--peer", peer]
        out = run_vaultmesh_cmd(cmd)
        return json.loads(out)
    except Exception:
        return {}


def _directory_supports_private_mode(directory: Path) -> bool:
    """Return whether files in *directory* can actually retain mode 0600."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    probe = directory / (
        f".quote-client-mode-{os.getpid()}-{threading.get_ident()}-"
        f"{secrets.token_hex(4)}"
    )
    fd = -1
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        fd = -1
        return probe.stat().st_mode & 0o777 == 0o600
    except OSError:
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            probe.unlink()
        except OSError:
            pass


def _quote_client_identity_path() -> Path:
    """Choose stable storage that can enforce private key permissions.

    Windows/WSL mounted filesystems can report every file as 0777 even after a
    successful chmod.  The VaultMesh client intentionally rejects such key
    files, so use a private native-filesystem state directory in that case.
    The workspace hash keeps concurrent DOs isolated while remaining stable
    across their retry processes.
    """
    workspace = Path(C.BASE_DIR).resolve()
    preferred_dir = workspace / "transfer_jobs"
    if _directory_supports_private_mode(preferred_dir):
        return preferred_dir / "quote-client-identity.key"

    secure_root = Path(
        os.environ.get("FILETRUST_SECURE_STATE_DIR", tempfile.gettempdir())
    ) / "filetrust-quote-identities"
    secure_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(secure_root, 0o700)
    except OSError:
        pass
    if not _directory_supports_private_mode(secure_root):
        raise RuntimeError(
            "no filesystem capable of enforcing mode 0600 is available for "
            "the durable VaultMesh quote identity; set FILETRUST_SECURE_STATE_DIR"
        )
    namespace = hashlib.sha256(str(workspace).encode("utf-8")).hexdigest()
    return secure_root / f"{namespace}.key"


def quote_refusal_retires_transfer_id(refusal: dict | None) -> bool:
    """Is this refusal final for THIS transferId, whatever the cluster does next?

    A keeper keeps the durable quote reservation bound to a transferId after that
    reservation settles. Once it settled without delivering anything -- expired, or
    released -- no later retry under the same id can ever be accepted, so the
    caller must stop waiting and let the pre-obligation cancellation retire the id.

    ``stored`` and ``deletion_pending`` are deliberately NOT included. Those mean
    the keeper is holding, or was holding, real data for this id, so the transfer
    has to resume against that same keeper rather than be reissued elsewhere.
    """
    if not refusal:
        return False
    if refusal.get("busy"):
        return False
    return str(refusal.get("settled_state", "") or "").strip().lower() in {
        "expired",
        "released",
    }


# Phase 2: what this app's VaultMesh program can relay, asked once per executable file.
_VAULTMESH_CAPABILITIES: dict = {}
_CAPABILITY_TIMEOUT_SECONDS = 20


def vaultmesh_relays_quote_link_nonce() -> bool:
    """Whether this app's VaultMesh program passes the keeper's quote link nonce through.

    A program built before the escrow-link change decodes the keeper's reply into a
    structure without that field and prints it again, so the nonce is lost; it also does
    not know the question, and any failure, timeout or unreadable answer counts as
    unable. App updates replace the Python code, not this program (ft_transfer.py
    installs it, release-pinned), so the answer is asked of the file on disk, and asked
    again when that file changes.
    """
    path = str(C.VAULTMESH_CMD)
    try:
        info = os.stat(path)
    except OSError:
        return False
    key = (path, info.st_size, info.st_mtime_ns)
    if key not in _VAULTMESH_CAPABILITIES:
        relays = False
        try:
            result = subprocess.run(
                [path, "--mode", "capabilities"], capture_output=True, text=True,
                timeout=_CAPABILITY_TIMEOUT_SECONDS,
            )
            if result.returncode == 0:
                answer = json.loads(result.stdout)
                relays = isinstance(answer, dict) and answer.get("quoteLinkNonce") is True
        except (OSError, subprocess.SubprocessError, ValueError):
            relays = False
        _VAULTMESH_CAPABILITIES[key] = relays
    return _VAULTMESH_CAPABILITIES[key]


def _get_quote(
    peer: str, file_size: int, service_end: int, transfer_id: str = "",
    refusal: dict | None = None,
    *,
    file_id: str = "",
    vk_address: str = "",
) -> dict | None:
    """Call VK QuoteProtocol before storing: returns QuoteResp dict or None on failure.

    Only attempted when VKEscrow is configured on the DO side and both file_size
    and service_end are positive.  Failure is non-fatal — the store proceeds without
    escrow if VK doesn't support the quote protocol or returns an error.

    When the keeper refuses, its stated reason is recorded in ``refusal`` so the
    caller can distinguish a keeper that is momentarily busy from one that is
    simply full.  Without it every refusal collapses into the same generic
    "no durable payment commitment" message and a caller cannot tell a condition
    that will pass from one that never will.
    """
    if C.vk_escrow is None:
        return None
    if file_size <= 0 or service_end <= 0:
        return None
    # Once the refund contracts need the quote's link nonce, a VaultMesh program that
    # drops it must not ask for quotes: each one has the keeper reserve capacity on chain
    # for an escrow this app would then refuse to pay.
    if CH.escrow_link_required() and not vaultmesh_relays_quote_link_nonce():
        reason = (
            "the transfer program is too old to relay quote link nonces; "
            "update it (ft_transfer.py) before storing"
        )
        L.log(f"[escrow] {reason}")
        if refusal is not None:
            refusal["reason"] = reason
            refusal["peer"] = peer
            refusal["busy"] = False
        return None
    # The keeper issues a quote only to the owner of a real file whose key
    # generation is finished, and the signature names the keeper and the
    # transferId. Without the file or the keeper's address there is nothing to
    # sign, and an unsigned request is refused.
    vk_address = str(vk_address or "").strip() or _vk_address_from_peer(peer)
    if not file_id or not vk_address:
        reason = (
            "cannot sign quote request: "
            + ("fileId missing" if not file_id else "VK address unknown")
        )
        L.log(f"[escrow] {reason}")
        if refusal is not None:
            refusal["reason"] = reason
            refusal["peer"] = peer
        return None
    if not transfer_id:
        transfer_id = "ftq_" + secrets.token_hex(24)
    try:
        uploader, issued_at, quote_sig = build_vaultmesh_quote_auth(
            transfer_id, file_id, int(file_size), int(service_end), vk_address,
        )
        cmd = [
            C.VAULTMESH_CMD,
            "--mode",        "quote",
            "--peer",        peer,
            "--size",        str(file_size),
            "--service-end", str(service_end),
            # A durable VK quote is bound to the requesting libp2p identity.
            # Without this key every CLI retry has a new identity and the VK
            # correctly rejects the reused transferId as different metadata.
            "--client-identity-key",
            str(_quote_client_identity_path()),
        ]
        cmd.extend([
            "--transfer-id", transfer_id,
            "--file-id", HX.prefixed_file_id(file_id),
            "--uploader", uploader,
            "--transfer-issued-at", str(issued_at),
            "--transfer-sig", quote_sig,
        ])
        out  = run_vaultmesh_cmd(cmd)
        resp = json.loads(out)
        if not resp.get("ok"):
            reason = str(resp.get("err", "unknown error"))
            L.log(f"[escrow] quote failed: {reason}")
            if refusal is not None:
                refusal["reason"] = reason
                refusal["peer"] = peer
                # Structured, not prose. "Retry me" and "this transferId is
                # finished" need opposite handling and must not be told apart by
                # matching an error string.
                refusal["busy"] = bool(resp.get("busy"))
                refusal["settled_state"] = str(
                    resp.get("quoteSettledState", "") or ""
                ).strip().lower()
            return None
        L.log(f"[escrow] quote received  pc={resp.get('paymentCommitment','')[:18]}...  price={resp.get('agreedPriceWei','0')} wei")
        return resp
    except Exception as exc:
        L.log(f"[escrow] quote error: {exc}")
        if refusal is not None:
            refusal["reason"] = str(exc)
            refusal["peer"] = peer
        return None


def bytes32_from_hex(value: str, label: str) -> bytes:
    return HX.hex_to_bytes(value, expected_bytes=32, field=label)


def latest_chain_timestamp() -> int:
    if C.w3 is None:
        raise RuntimeError("blockchain connection is unavailable")
    latest = C.w3.eth.get_block("latest")
    timestamp = int(latest["timestamp"])
    if timestamp <= 0:
        raise RuntimeError("blockchain returned an invalid latest-block timestamp")
    return timestamp


# Phase 2: the views of FileTrustAddressRegistry this check reads.
_REGISTRY_ABI = [
    {"type": "function", "name": "chainId", "stateMutability": "view", "inputs": [],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "nameOf", "stateMutability": "view",
     "inputs": [{"name": "", "type": "address"}], "outputs": [{"name": "", "type": "bytes32"}]},
    {"type": "function", "name": "versionOf", "stateMutability": "view",
     "inputs": [{"name": "", "type": "address"}], "outputs": [{"name": "", "type": "uint32"}]},
    {"type": "function", "name": "latestVersion", "stateMutability": "view",
     "inputs": [{"name": "name", "type": "bytes32"}], "outputs": [{"name": "", "type": "uint32"}]},
    {"type": "function", "name": "entry", "stateMutability": "view",
     "inputs": [{"name": "name", "type": "bytes32"}, {"name": "version", "type": "uint32"}],
     "outputs": [{"name": "", "type": "tuple", "components": [
         {"name": "addr", "type": "address"}, {"name": "registeredAt", "type": "uint64"},
         {"name": "status", "type": "uint8"}, {"name": "codeHash", "type": "bytes32"},
         {"name": "abiHash", "type": "bytes32"}]}]},
]
_REGISTRY_CHECK: dict = {}
_REGISTRY_CHECK_SECONDS = 600


def registry_blocks_new_obligations() -> str:
    """Why no new obligation may be paid for now, or "" when nothing stands against it.

    Only when ADDRESS_REGISTRY_ADDRESS is configured: the contracts this DO pays and
    refunds escrows through are checked against the on-chain registry
    (do_deployment_manifest.verify_against_registry). A failed check, or a registry that
    cannot be read, blocks new escrows; it never changes an address. The answer is kept
    for ten minutes, a failure for one.
    """
    registry_address = str(getattr(C.config, "ADDRESS_REGISTRY_ADDRESS", "") or "").strip()
    if not registry_address:
        return ""
    now = time.time()
    cached = _REGISTRY_CHECK.get(registry_address)
    if cached and cached[0] > now:
        return cached[1]
    from . import do_deployment_manifest as DM
    pinned = {
        name: contract.address
        for name, contract in (
            ("VKEscrow", C.vk_escrow),
            ("StorageRegistrationTimeout", getattr(C, "storage_registration_timeout", None)),
            ("StorageReceiptDispute", getattr(C, "storage_receipt_dispute", None)),
        )
        if contract is not None
    }
    try:
        registry = C.w3.eth.contract(address=C.w3.to_checksum_address(registry_address), abi=_REGISTRY_ABI)
        name_of = lambda raw: bytes(raw).rstrip(b"\0").decode("utf-8", "replace")
        key_of = lambda name: name.encode("utf-8").ljust(32, b"\0")
        result = DM.verify_against_registry(
            pinned,
            chain_id=int(C.w3.eth.chain_id),
            registry_chain_id=int(registry.functions.chainId().call()),
            lookup=lambda address: (
                name_of(registry.functions.nameOf(address).call()),
                int(registry.functions.versionOf(address).call()),
            ),
            entry=lambda name, version: dict(zip(
                ("addr", "registeredAt", "status", "codeHash", "abiHash"),
                registry.functions.entry(key_of(name), version).call(),
            )),
            latest_version=lambda name: int(registry.functions.latestVersion(key_of(name)).call()),
            code_hash=lambda address: "0x" + bytes(Web3.keccak(C.w3.eth.get_code(address))).hex(),
        )
        if result["newer"]:
            L.log(f"[registry] newer contract versions are registered: {', '.join(result['newer'])}; "
                  "this app keeps its own until a verified update")
        reason, ttl = "", _REGISTRY_CHECK_SECONDS
    except DM.DeploymentManifestError as exc:
        reason, ttl = str(exc), 60
    except Exception as exc:
        reason, ttl = f"address registry unavailable: {exc}", 60
    if reason:
        L.log(f"[registry] new escrows are blocked: {reason}")
    _REGISTRY_CHECK[registry_address] = (now + ttl, reason)
    return reason


def _link_opens(
    payment_commitment: str,
    registration_commitment: str,
    link_nonce: str,
    link_commitment: str,
) -> bool:
    """keccak256(paymentCommitment ++ registrationCommitment ++ linkNonce) == linkCommitment."""
    try:
        opened = Web3.solidity_keccak(
            ["bytes32", "bytes32", "bytes32"],
            [
                bytes32_from_hex(payment_commitment, "paymentCommitment"),
                bytes32_from_hex(registration_commitment, "registrationCommitment"),
                bytes32_from_hex(link_nonce, "linkNonce"),
            ],
        )
        return bytes(opened) == bytes32_from_hex(link_commitment, "linkCommitment")
    except Exception:
        return False


def _prepare_escrow_quote(
    quote: dict,
    file_size: int,
    service_end: int,
    vk_peer_addr: str,
    item: dict,
    vk_expected_address: str = "",
) -> dict | None:
    blocked = registry_blocks_new_obligations()
    if blocked:
        L.log(f"[escrow] contract registry check failed: {blocked} — deposit skipped")
        item["escrowDepositSkipped"] = f"contract registry check failed: {blocked}"
        return None
    from . import do_release_checks as RC
    blocked = RC.new_obligations_blocked()
    if blocked:
        L.log(f"[escrow] release check failed: {blocked} — deposit skipped")
        item["escrowDepositSkipped"] = f"release check failed: {blocked}"
        return None
    payment_commitment = quote.get("paymentCommitment", "")
    size_commitment = quote.get("sizeCommitment", "")
    link_commitment = quote.get("linkCommitment", "")
    registration_commitment = quote.get("registrationCommitment", "")
    agreed_price_wei = quote.get("agreedPriceWei", "0")
    quote_valid_until = int(quote.get("quoteValidUntil", 0) or 0)
    vk_signature = str(quote.get("vkSignature", "") or "")
    quote_service_end = int(quote.get("serviceEnd", 0) or 0)
    quote_escrow = str(quote.get("vkEscrowContract", "") or "")
    capacity_proof_address = str(quote.get("capacityProofContract", "") or "")
    reserved_capacity_bytes = int(quote.get("reservedCapacityBytes", 0) or 0)
    reservation_expires_at = int(quote.get("reservationExpiresAt", 0) or 0)
    reservation_tx_hash = str(quote.get("reservationTxHash", "") or "")
    transfer_deadline = int(quote.get("transferDeadline", 0) or 0)
    quote_version = int(quote.get("quoteVersion", 0) or 0)
    link_nonce = str(quote.get("linkNonce", "") or "")

    if (
        not payment_commitment or not size_commitment or not link_commitment or
        not registration_commitment or quote_valid_until <= 0 or not vk_signature or
        not capacity_proof_address or reserved_capacity_bytes < int(file_size) or
        reservation_expires_at < quote_valid_until or transfer_deadline < reservation_expires_at or
        quote_version != 2
    ):
        L.log("[escrow] incomplete quote — deposit skipped")
        return None
    # The escrow is refunded on chain only to settle the registration its link
    # commitment opens to (Phase 1D D18/D19); the keeper gives the nonce with the quote.
    if link_nonce:
        if not _link_opens(payment_commitment, registration_commitment, link_nonce, link_commitment):
            L.log("[escrow] the quote's link nonce does not open its link commitment — deposit skipped")
            item["escrowDepositSkipped"] = "link nonce does not open the link commitment"
            return None
    elif CH.escrow_link_required():
        L.log("[escrow] quote has no link nonce, so its escrow could not be refunded — deposit skipped")
        item["escrowDepositSkipped"] = "quote has no link nonce"
        return None
    if service_end <= 0:
        L.log("[escrow] serviceEnd missing — deposit skipped")
        return None
    if quote_service_end != int(service_end):
        L.log("[escrow] signed quote serviceEnd mismatch — deposit skipped")
        return None
    try:
        chain_now = latest_chain_timestamp()
    except Exception as exc:
        L.log(f"[escrow] blockchain time unavailable: {exc} — deposit aborted")
        item["escrowDepositSkipped"] = "blockchain time unavailable"
        return None

    if quote_valid_until <= chain_now:
        L.log(
            f"[escrow] signed quote expired by blockchain time "
            f"(deadline={quote_valid_until}, chain={chain_now}) — deposit aborted"
        )
        item["escrowDepositSkipped"] = "signed quote expired"
        return None

    price_wei = int(agreed_price_wei or 0)
    if price_wei <= 0:
        L.log("[escrow] agreedPriceWei is zero — deposit skipped")
        item["escrowDepositSkipped"] = "agreedPriceWei zero"
        return None

    vk_addr = str(vk_expected_address or "").strip() or _vk_address_from_peer(
        vk_peer_addr
    )
    if not vk_addr or C.vk_escrow is None:
        L.log(
            "[escrow] cannot bind signed quote to VK/escrow — deposit skipped "
            f"peerId={peer_id_from_peer(vk_peer_addr)} "
            f"registryRows={len(getattr(S, 'vault_keeper_rows', None) or {})}"
        )
        return None
    try:
        expected_escrow = C.w3.to_checksum_address(C.vk_escrow.address)
        if C.w3.to_checksum_address(quote_escrow) != expected_escrow:
            raise ValueError("quote escrow contract mismatch")
        # uint64 chain id: the layout StorageRegistrationTimeout.
        # resolveRegistrationTimeout packs, the only on-chain verifier of this
        # digest, and the one the keeper signs (receipt.go signAdmissionQuoteV2).
        #
        # This packed uint256 until 2026-10-02. The keeper had been moved to
        # uint64 the day before to match the contract and this check was not, so
        # every quote from a correct keeper failed here and no escrow was ever
        # deposited: each keeper held a reservation for every attempt, and
        # nothing reached the chain.
        digest = C.w3.solidity_keccak(
            [
                "string", "uint64", "address", "address", "bytes32", "bytes32",
                "bytes32", "bytes32", "uint256", "uint64", "uint64", "uint64",
            ],
            [
                "FileTrustAdmissionQuoteV2", int(C.w3.eth.chain_id),
                C.w3.to_checksum_address(vk_addr), expected_escrow,
                bytes32_from_hex(payment_commitment, "paymentCommitment"),
                bytes32_from_hex(registration_commitment, "registrationCommitment"),
                bytes32_from_hex(size_commitment, "sizeCommitment"),
                bytes32_from_hex(link_commitment, "linkCommitment"),
                price_wei, int(service_end), quote_valid_until, transfer_deadline,
            ],
        )
        from eth_account import Account
        from eth_account.messages import encode_defunct
        recovered = Account.recover_message(
            encode_defunct(primitive=bytes(digest)), signature=vk_signature,
        )
        if C.w3.to_checksum_address(recovered) != C.w3.to_checksum_address(vk_addr):
            raise ValueError("quote signer does not match selected VK")
    except Exception as exc:
        L.log(f"[escrow] signed quote verification failed: {exc} — deposit skipped")
        item["escrowDepositSkipped"] = "invalid VK-signed quote"
        return None

    # A VK signature alone cannot prevent concurrent signed quotes from
    # overbooking capacity. Confirm the privacy-safe registration commitment is
    # actively reserved by this VK in the authoritative capacity contract before
    # sending any escrow value.
    if C.capacity_proof_sc is None:
        L.log("[escrow] CapacityProofSC unavailable — deposit aborted")
        item["escrowDepositSkipped"] = "CapacityProofSC unavailable"
        return None
    try:
        expected_capacity_proof = C.w3.to_checksum_address(C.capacity_proof_sc.address)
        if C.w3.to_checksum_address(capacity_proof_address) != expected_capacity_proof:
            raise ValueError("quote capacity proof contract mismatch")
        reservation = C.capacity_proof_sc.functions.getQuoteReservation(
            bytes32_from_hex(registration_commitment, "registrationCommitment")
        ).call()
        reserved_vk = C.w3.to_checksum_address(reservation[0])
        chain_reserved_bytes = int(reservation[1])
        chain_expires_at = int(reservation[2])
        chain_state = int(reservation[3])
        if reserved_vk != C.w3.to_checksum_address(vk_addr):
            raise ValueError("capacity reservation belongs to another VK")
        if chain_state != 1:
            raise ValueError(f"capacity reservation is not active (state={chain_state})")
        if chain_reserved_bytes != reserved_capacity_bytes or chain_reserved_bytes < int(file_size):
            raise ValueError("capacity reservation byte bound mismatch")
        if chain_expires_at != reservation_expires_at or chain_expires_at <= chain_now:
            raise ValueError("capacity reservation deadline mismatch or expired")
    except Exception as exc:
        L.log(f"[escrow] authoritative capacity reservation verification failed: {exc} — deposit aborted")
        item["escrowDepositSkipped"] = "capacity reservation unavailable or invalid"
        return None

    if C.vault_keeper_registry is None:
        L.log("[escrow] VK registry unavailable — deposit aborted")
        item["escrowDepositSkipped"] = "VK registry unavailable"
        return None
    if vk_addr:
        try:
            profile = C.vault_keeper_registry.functions.getVaultKeeper(
                C.w3.to_checksum_address(vk_addr)
            ).call()
            vk_storage_fee = int(profile[1])
            stake_wei = int(profile[2])
            min_vk_stake = _minimum_vk_stake_wei()
            if not bool(profile[3]) or stake_wei < min_vk_stake:
                L.log(f"[escrow] VK {vk_addr} is not eligible stake={stake_wei} min={min_vk_stake} — deposit aborted")
                item["escrowDepositSkipped"] = "VK not eligible"
                return None
            su_to_wei = int(getattr(C.config, "SU_TO_WEI_RATE", 0) or 0)
            import math
            duration_days = math.ceil(max(0, service_end - chain_now) / 86400)
            size_gb = file_size / 1_000_000_000
            # Always judged, never skipped. The two conditions this used to be
            # guarded by -- a zero advertised fee and a missing rate -- were the
            # two ways to be charged anything at all.
            price_ok, price_reason = quoted_price_is_acceptable(
                price_wei=price_wei, fee_su_per_gb_day=vk_storage_fee,
                size_bytes=file_size, duration_days=duration_days, su_to_wei=su_to_wei,
                hold_fee_wei=_quote_hold_fee_allowance_wei(),
                minimum_price_wei=_escrow_piece_tx_cost_wei(),
            )
            if not price_ok:
                L.log(f"[escrow] {price_reason} — deposit aborted")
                item["escrowDepositSkipped"] = "agreedPriceWei rejected"
                return None
            L.log(f"[escrow] price ok  {price_wei} wei  storageFee={vk_storage_fee} SU/GB/day  sizeGB={size_gb:.6f}  days={duration_days}")
        except Exception as exc:
            L.log(f"[escrow] registry price/eligibility check failed: {exc} — deposit aborted")
            item["escrowDepositSkipped"] = "VK registry verification unavailable"
            return None

    return {
        "paymentCommitment": payment_commitment,
        "sizeCommitment": size_commitment,
        "linkCommitment": link_commitment,
        "linkNonce": link_nonce,
        # The escrow lives in this VKEscrow version for its whole life (Phase 2), so it is
        # reclaimed there even after the app moves to a newer version.
        "vkEscrowContract": C.w3.to_checksum_address(quote_escrow),
        "registrationCommitment": registration_commitment,
        "priceWei": price_wei,
        "serviceEnd": int(service_end),
        "quoteValidUntil": quote_valid_until,
        "vkSignature": vk_signature,
        "vkAddress": vk_addr,
        "capacityProofContract": capacity_proof_address,
        "reservedCapacityBytes": reserved_capacity_bytes,
        "reservationExpiresAt": reservation_expires_at,
        "reservationTxHash": reservation_tx_hash,
        "transferDeadline": transfer_deadline,
        "quoteVersion": quote_version,
    }


def _quote_hold_fee_allowance_wei() -> int:
    """The most a keeper may add to a quote for holding its capacity.

    A keeper spends two transactions per quote -- the hold and its release --
    and charges them inside the quoted price (its --quote-hold-gas, measured at
    282,351 + 33,123 gas and rounded up to 400,000). The data owner allows that
    much gas at the network's fixed gas price, and no more.
    """
    gas = max(0, _config_int("DO_QUOTE_HOLD_GAS_MAX", 400_000))
    gas_price = max(0, C.gas_price_wei())
    return gas * gas_price


def _escrow_piece_tx_cost_wei() -> int:
    """VKEscrow.deletionTxCostEstimate: the lowest storage price a keeper quotes.

    The escrow pays a keeper this much on top of its time share when the owner
    deletes early -- the keeper's own store and delete transactions for one
    piece -- and it can never pay out more than was deposited, so a keeper never
    quotes below it. Read from the same contract the keeper reads, so the two
    cannot disagree. Unreadable means 0: the check stays strict and a quote
    priced at the minimum is refused rather than paid on trust.
    """
    try:
        if C.vk_escrow is None:
            return 0
        return max(0, int(C.vk_escrow.functions.deletionTxCostEstimate().call()))
    except Exception:
        return 0


def quoted_price_is_acceptable(
    *, price_wei: int, fee_su_per_gb_day: int, size_bytes: int,
    duration_days: int, su_to_wei: int, hold_fee_wei: int = 0,
    minimum_price_wei: int = 0,
) -> tuple[bool, str]:
    """Is this quote within what the keeper advertised on chain?

    The registry fee is the only figure the owner can hold a keeper to, so the
    quote is measured against it, plus one day of slack for rounding and clock
    differences between the two sides.

    Two cases used to skip this check rather than fail it, and both were ways to
    be charged anything at all:

    A keeper advertising a zero fee. That keeper is the cheapest in the network
    and scores best on cost, so it is selected first -- and with a zero fee
    there was nothing to compare against, so the comparison was skipped and the
    signed quote was taken at its word. Advertising zero is a promise to charge
    zero, not permission to charge anything.

    A missing conversion rate. With no way to value a price, the check cannot be
    performed -- which is a reason to stop, not a reason to pay.

    ``hold_fee_wei`` is the most the keeper may add for holding its capacity
    before payment (see _quote_hold_fee_allowance_wei). It is allowed on top of
    a real storage price only: a keeper advertising zero refuses to quote at
    all, so zero still means zero, hold fee included.

    ``minimum_price_wei`` is the escrow's per-piece cost (see
    _escrow_piece_tx_cost_wei). A keeper raises a small or short piece's storage
    price to it, so it replaces the expected price when it is higher -- again
    only when there is a real storage price.
    """
    price_wei = int(price_wei)
    if price_wei < 0:
        return False, "agreedPriceWei is negative"
    if int(su_to_wei) <= 0:
        return False, "agreedPriceWei cannot be valued: no SU_TO_WEI_RATE configured"

    expected_max = _vk_storage_price_wei(fee_su_per_gb_day, size_bytes, duration_days, su_to_wei)
    tolerance = _vk_storage_price_wei(fee_su_per_gb_day, size_bytes, 1, su_to_wei)
    hold_fee_wei = max(0, int(hold_fee_wei)) if expected_max > 0 else 0
    minimum = max(0, int(minimum_price_wei)) if expected_max > 0 else 0
    storage_allowed = max(expected_max + tolerance, minimum)
    if price_wei > storage_allowed + hold_fee_wei:
        return False, (
            f"agreedPriceWei {price_wei} exceeds expected {expected_max} "
            f"(+{tolerance} tolerance, minimum {minimum}, +{hold_fee_wei} hold fee) "
            f"for fee={fee_su_per_gb_day} SU/GB/day"
        )
    return True, "ok"


def _vk_storage_price_wei(fee_su_per_gb_day: int, size_bytes: int, duration_days: int, su_to_wei: int) -> int:
    numerator = (
        int(fee_su_per_gb_day)
        * max(0, int(size_bytes))
        * max(0, int(duration_days))
        * int(su_to_wei)
    )
    denominator = 1_000_000_000
    if numerator <= 0:
        return 0
    return (numerator + denominator - 1) // denominator


def _deposit_escrow_from_quote_info(item: dict, quote_info: dict) -> str:
    payment_commitment = quote_info["paymentCommitment"]
    try:
        pc_bytes = bytes32_from_hex(payment_commitment, "paymentCommitment")
        sc_bytes = bytes32_from_hex(quote_info["sizeCommitment"], "sizeCommitment")
        lc_bytes = bytes32_from_hex(quote_info["linkCommitment"], "linkCommitment")
        price_wei = int(quote_info["priceWei"])
        service_end = int(quote_info["serviceEnd"])
        transfer_deadline = int(quote_info.get("transferDeadline", 0) or 0)
        max_registration_timeout = int(
            C.vk_escrow.functions.maxRegistrationTimeoutSeconds().call()
        )
        chain_now = latest_chain_timestamp()
        if transfer_deadline <= chain_now or transfer_deadline > chain_now + max_registration_timeout:
            raise RuntimeError("signed transfer deadline is outside the escrow safety bounds")
        hybrid_mode = _hybrid_escrow_enabled()
        deposit_fn = "depositEscrowV2"
        deposit_value_wei = price_wei
        if hybrid_mode:
            deposit_fn = "depositEscrowBondV2"
            deposit_value_wei = _hybrid_bond_wei(price_wei)

        # A mined deposit may exist even if the DO process stopped before its
        # local job file was updated. Recover and validate it instead of ever
        # creating a second economic obligation.
        existing = C.vk_escrow.functions.escrows(pc_bytes).call()
        if int(existing[0]) > 0:
            if C.w3.to_checksum_address(existing[9]) != C.w3.to_checksum_address(C.DO):
                raise RuntimeError("existing escrow belongs to a different depositor")
            if bytes(existing[3]) != sc_bytes or bytes(existing[4]) != lc_bytes:
                raise RuntimeError("existing escrow commitments do not match durable quote")
            if int(existing[2]) != service_end:
                raise RuntimeError("existing escrow serviceEnd does not match durable quote")
            if int(existing[1]) > int(quote_info["quoteValidUntil"]):
                raise RuntimeError("existing escrow was deposited after the signed quote expired")
            if int(existing[10]) != transfer_deadline:
                raise RuntimeError("existing escrow registration deadline does not match signed quote")
            if int(existing[0]) < deposit_value_wei:
                raise RuntimeError("existing escrow amount is below the durable quote requirement")
            if not hybrid_mode and not bool(existing[5]):
                raise RuntimeError("existing escrow is not finalized")
            item["escrowDepositWei"] = int(existing[0])
            item["escrowExpectedTotalWei"] = price_wei
            item["escrowPendingFinalize"] = not bool(existing[5])
            item["escrowRecoveredOnChain"] = True
            item["paymentCommitment"] = payment_commitment
            if quote_info.get("registrationCommitment"):
                item["registrationCommitment"] = quote_info["registrationCommitment"]
            L.log(f"[escrow] recovered existing deposit  pc={payment_commitment[:18]}...")
            return payment_commitment

        if int(quote_info["quoteValidUntil"]) <= chain_now:
            raise RuntimeError(
                "signed quote expired before escrow deposit "
                f"(deadline={int(quote_info['quoteValidUntil'])}, chain={chain_now})"
            )
        with TM.account_transaction_lock(C.DO), _escrow_tx_lock:
            nonce = TM.pending_nonce(C.w3, C.DO)
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="getTransactionCount",
                actor_address=C.DO,
                status="success",
                nonce=nonce,
                target_function=deposit_fn,
            )
            gas_price = C.gas_price_wei()
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="gasPrice",
                actor_address=C.DO,
                status="success",
                result=gas_price,
                target_function=deposit_fn,
            )
            if hybrid_mode:
                tx_builder = C.vk_escrow.functions.depositEscrowBondV2
            else:
                tx_builder = C.vk_escrow.functions.depositEscrowV2
            fn = tx_builder(
                pc_bytes, sc_bytes, lc_bytes, service_end, transfer_deadline
            )
            # Current escrow records can exceed the former fixed 200k limit.
            # Match batch deposits: estimate the exact call before signing.
            gas_est = fn.estimate_gas({"from": C.DO, "value": deposit_value_wei})
            tx = fn.build_transaction({
                "from": C.DO,
                "value": deposit_value_wei,
                "nonce": nonce,
                "gas": gas_est + 80_000,
                "gasPrice": gas_price,
            })
            signed = C.DO_ACCOUNT.sign_transaction(tx)
            tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt_tx = C.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            TX.log_contract_transaction(
                C,
                C.w3,
                actor_address=C.DO,
                contract_name="VKEscrow",
                function_name=deposit_fn,
                contract_address=C.vk_escrow.address,
                tx=tx,
                tx_hash=tx_hash,
                receipt=receipt_tx,
                payment_commitment=payment_commitment,
                price_wei=deposit_value_wei,
                service_end=service_end,
            )
        if receipt_tx.status == 1:
            L.log(f"[escrow] deposited {deposit_value_wei} wei  pc={payment_commitment[:18]}...  tx={tx_hash.hex()[:18]}...")
            item["escrowDepositTx"] = tx_hash.hex()
            item["escrowDepositWei"] = deposit_value_wei
            item["escrowExpectedTotalWei"] = price_wei
            item["escrowPendingFinalize"] = bool(hybrid_mode and price_wei > deposit_value_wei)
            if hybrid_mode:
                item["escrowMode"] = "hybrid-bond-first"
            item["paymentCommitment"] = payment_commitment
            if quote_info.get("registrationCommitment"):
                item["registrationCommitment"] = quote_info.get("registrationCommitment")
            return payment_commitment
        L.log(f"[escrow] deposit tx reverted  tx={tx_hash.hex()[:18]}...")
        item["escrowDepositFailed"] = tx_hash.hex()
        return ""
    except Exception as exc:
        TX.log_contract_transaction_attempt(
            C,
            actor_address=C.DO,
            contract_name="VKEscrow",
            function_name=deposit_fn if 'deposit_fn' in locals() else "depositEscrow",
            contract_address=getattr(C.vk_escrow, "address", ""),
            status="failed",
            error=str(exc),
            payment_commitment=payment_commitment,
            price_wei=quote_info.get("priceWei", 0),
            service_end=quote_info.get("serviceEnd", 0),
        )
        L.log(f"[escrow] deposit error: {exc}")
        item["escrowDepositError"] = str(exc)
        return ""


def _registration_attempt_state(job: dict) -> tuple[str, str, int]:
    """Return (state, commitmentHash, deadline) for an ambiguous peer attempt."""
    quote = job.get("quoteInfo") if isinstance(job.get("quoteInfo"), dict) else {}
    escrow = job.get("escrow") if isinstance(job.get("escrow"), dict) else {}
    registration_commitment = str(quote.get("registrationCommitment", "") or "")
    payment_commitment = str(
        escrow.get("paymentCommitment", "") or quote.get("paymentCommitment", "") or ""
    )
    if not registration_commitment or not payment_commitment:
        return "pre_obligation", "", 0
    if C.file_registration_sc is None or C.vk_escrow is None:
        return "unknown", "", 0
    rc = bytes32_from_hex(registration_commitment, "registrationCommitment")
    pc = bytes32_from_hex(payment_commitment, "paymentCommitment")
    commitment_hash_raw = C.file_registration_sc.functions.registrationCommitmentToCommitmentHash(rc).call()
    commitment_hash = "0x" + bytes(commitment_hash_raw).hex()
    if int.from_bytes(bytes(commitment_hash_raw), "big") == 0:
        commitment_hash = ""
    deadline = int(C.vk_escrow.functions.registrationDeadlineOf(pc).call())
    latest = C.w3.eth.get_block("latest")
    chain_now = int(latest["timestamp"])
    if commitment_hash:
        record = C.file_registration_sc.functions.fileRecords(
            bytes32_from_hex(commitment_hash, "commitmentHash")
        ).call()
        registered_at = int(record[6])
        if deadline > 0 and registered_at <= deadline:
            return "registered_on_time", commitment_hash, deadline
        if deadline > 0 and chain_now > deadline:
            return "registered_late", commitment_hash, deadline
        return "registered", commitment_hash, deadline
    if deadline > 0 and chain_now > deadline:
        return "expired_unregistered", "", deadline
    return "waiting", "", deadline


def _registration_timeout_call(
    vk_address: str, payment_bytes: bytes, registration_bytes: bytes, quote: dict,
):
    """The resolveRegistrationTimeout call for this V2 quote, in the deployed form.

    From Phase 1D the resolver refunds only the registration the escrow's link
    commitment opens to, so it takes the quote's link nonce; an older one takes none.
    """
    contract = CH.escrow_contracts(str(quote.get("vkEscrowContract", "") or ""))["storage_registration_timeout"]
    vk = C.w3.to_checksum_address(vk_address)
    terms = (
        int(quote["priceWei"]),
        int(quote["quoteValidUntil"]),
        int(quote["transferDeadline"]),
        bytes.fromhex(str(quote["vkSignature"]).removeprefix("0x")),
    )
    if not CH.takes_link_nonce(contract, "resolveRegistrationTimeout"):
        return contract.functions.resolveRegistrationTimeout(
            vk, payment_bytes, registration_bytes, *terms,
        )
    link_nonce = str(quote.get("linkNonce", "") or "")
    if not link_nonce:
        raise XFER.TransferPending(
            "registration deadline elapsed but the quote has no link nonce; "
            "its escrow can be taken back after the service end and grace"
        )
    return contract.get_function_by_signature(
        "resolveRegistrationTimeout(address,bytes32,bytes32,bytes32,uint256,uint64,uint64,bytes)"
    )(vk, payment_bytes, registration_bytes, bytes32_from_hex(link_nonce, "linkNonce"), *terms)


def _resolve_registration_timeout(job: dict, peer: str) -> bool:
    """Expire/refund an absent or late registration. Returns true only after mining."""
    state, commitment_hash, deadline = _registration_attempt_state(job)
    if state in {"registered_on_time", "registered", "waiting", "unknown"}:
        return False
    if state == "pre_obligation":
        # Absence of escrow is not proof that a running transfer sent no bytes.
        # Only jobs that never crossed the durable-transfer boundary may rotate
        # immediately; ambiguous running/response jobs must resume the same VK.
        return not XFER.requires_same_peer_resume(job)
    if C.storage_registration_timeout is None:
        raise XFER.TransferPending(
            "registration deadline elapsed but StorageRegistrationTimeout is not configured"
        )
    quote = job.get("quoteInfo") if isinstance(job.get("quoteInfo"), dict) else {}
    # The escrow's own deployment: an escrow paid before a V2 settings update keeps V1.
    timeout_contract = CH.escrow_contracts(str(quote.get("vkEscrowContract", "") or ""))["storage_registration_timeout"]
    escrow = job.get("escrow") if isinstance(job.get("escrow"), dict) else {}
    vk_address = str(quote.get("vkAddress", "") or _vk_address_from_peer(peer))
    payment_commitment = str(
        escrow.get("paymentCommitment", "") or quote.get("paymentCommitment", "") or ""
    )
    payment_bytes = bytes32_from_hex(payment_commitment, "paymentCommitment")
    registration_bytes = bytes32_from_hex(
        quote["registrationCommitment"], "registrationCommitment",
    )
    timeout_id = C.w3.solidity_keccak(
        ["string", "address", "bytes32", "bytes32"],
        [
            "registrationTimeout", C.w3.to_checksum_address(vk_address),
            payment_bytes, registration_bytes,
        ],
    )

    def already_resolved() -> bool:
        return bool(
            timeout_contract.functions.resolvedTimeouts(timeout_id).call()
        )

    def mark_expired(tx_hash_value: str = "") -> bool:
        XFER.update_upload_job(
            C.BASE_DIR, job, status="expired",
            registrationTimeoutTx=tx_hash_value,
            expiredCommitmentHash=commitment_hash,
            registrationDeadline=deadline,
        )
        return True

    if already_resolved():
        return mark_expired(str(job.get("registrationTimeoutTx", "") or ""))

    fn = _registration_timeout_call(vk_address, payment_bytes, registration_bytes, quote)
    try:
        with TM.account_transaction_lock(C.DO):
            nonce = TM.pending_nonce(C.w3, C.DO)
            gas_price = C.gas_price_wei()
            tx = fn.build_transaction({
                "from": C.DO, "nonce": nonce, "gas": 500_000, "gasPrice": gas_price,
            })
            signed = C.DO_ACCOUNT.sign_transaction(tx)
            tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = C.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            TX.log_contract_transaction(
                C, C.w3,
                actor_address=C.DO,
                contract_name="StorageRegistrationTimeout",
                function_name="resolveRegistrationTimeout",
                contract_address=timeout_contract.address,
                tx=tx,
                tx_hash=tx_hash,
                receipt=receipt,
                payment_commitment=payment_commitment,
                registration_commitment=quote["registrationCommitment"],
                registration_deadline=deadline,
                previous_commitment_hash=commitment_hash,
            )
    except Exception as exc:
        if already_resolved():
            return mark_expired("")
        raise XFER.TransferPending(
            f"registration-timeout result is still unknown: {exc}"
        ) from exc
    if receipt.status != 1:
        raise XFER.TransferPending("registration-timeout transaction reverted")
    mark_expired(tx_hash.hex())
    L.log(
        f"[store] expired ambiguous attempt peer={short_peer(peer)} "
        f"deadline={deadline} tx={tx_hash.hex()[:18]}..."
    )
    return True


def _deposit_escrow_batch(quote_items: list[dict]) -> bool:
    valid = [entry for entry in quote_items if entry.get("quoteInfo")]
    if len(valid) < 2 or C.vk_escrow is None:
        return False
    try:
        payment_commitments = [bytes32_from_hex(e["quoteInfo"]["paymentCommitment"], "paymentCommitment") for e in valid]
        size_commitments = [bytes32_from_hex(e["quoteInfo"]["sizeCommitment"], "sizeCommitment") for e in valid]
        link_commitments = [bytes32_from_hex(e["quoteInfo"]["linkCommitment"], "linkCommitment") for e in valid]
        service_ends = [int(e["quoteInfo"]["serviceEnd"]) for e in valid]
        registration_deadlines = [int(e["quoteInfo"]["transferDeadline"]) for e in valid]
        amounts = [int(e["quoteInfo"]["priceWei"]) for e in valid]
        total_value = sum(amounts)
        with TM.account_transaction_lock(C.DO), _escrow_tx_lock:
            nonce = TM.pending_nonce(C.w3, C.DO)
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="getTransactionCount",
                actor_address=C.DO,
                status="success",
                nonce=nonce,
                target_function="depositEscrowBatchV2",
            )
            gas_price = C.gas_price_wei()
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="gasPrice",
                actor_address=C.DO,
                status="success",
                result=gas_price,
                target_function="depositEscrowBatchV2",
            )
            fn = C.vk_escrow.functions.depositEscrowBatchV2(
                payment_commitments,
                size_commitments,
                link_commitments,
                service_ends,
                registration_deadlines,
                amounts,
            )
            try:
                gas_est = fn.estimate_gas({"from": C.DO, "value": total_value})
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=C.vk_escrow.address,
                    actor_address=C.DO,
                    status="success",
                    gas_estimate=gas_est,
                    target_function="depositEscrowBatchV2",
                    record_count=len(valid),
                )
            except Exception as exc:
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=C.vk_escrow.address,
                    actor_address=C.DO,
                    status="failed",
                    error=str(exc),
                    target_function="depositEscrowBatchV2",
                    record_count=len(valid),
                )
                gas_est = 200_000 * len(valid)
            tx = fn.build_transaction({
                "from": C.DO,
                "value": total_value,
                "nonce": nonce,
                "gas": gas_est + 80_000,
                "gasPrice": gas_price,
            })
            signed = C.DO_ACCOUNT.sign_transaction(tx)
            tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt_tx = C.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            TX.log_contract_transaction(
                C,
                C.w3,
                actor_address=C.DO,
                contract_name="VKEscrow",
                function_name="depositEscrowBatchV2",
                contract_address=C.vk_escrow.address,
                tx=tx,
                tx_hash=tx_hash,
                receipt=receipt_tx,
                record_count=len(valid),
                value_count=len(valid),
                payment_commitments=[e["quoteInfo"]["paymentCommitment"] for e in valid],
            )
        if receipt_tx.status != 1:
            L.log(f"[escrow] batch deposit reverted  tx={tx_hash.hex()[:18]}...")
            return False
        for entry in valid:
            info = entry["quoteInfo"]
            escrow = entry["escrow"]
            escrow["escrowDepositTx"] = tx_hash.hex()
            escrow["escrowDepositWei"] = int(info["priceWei"])
            escrow["paymentCommitment"] = info["paymentCommitment"]
            if info.get("registrationCommitment"):
                escrow["registrationCommitment"] = info.get("registrationCommitment")
            escrow["escrowDepositBatch"] = True
        L.log(f"[escrow] batch deposited {len(valid)} escrows total={total_value} wei tx={tx_hash.hex()[:18]}...")
        return True
    except Exception as exc:
        TX.log_contract_transaction_attempt(
            C,
            actor_address=C.DO,
            contract_name="VKEscrow",
            function_name="depositEscrowBatchV2",
            contract_address=getattr(C.vk_escrow, "address", ""),
            status="failed",
            error=str(exc),
            record_count=len(valid),
        )
        L.log(f"[escrow] batch deposit error: {exc}")
        return False


def _deposit_escrow_from_quote(item: dict, quote: dict, file_size: int, service_end: int, vk_peer_addr: str) -> str:
    """Deposit escrow on-chain using the pre-fetched quote. Returns paymentCommitment on
    success (use it in the subsequent StoreReq), or '' if deposit was skipped/failed.

    depositEscrow(bytes32 paymentCommitment, bytes32 sizeCommitment,
                  bytes32 linkCommitment, uint64 serviceEnd) payable
    """
    info = _prepare_escrow_quote(quote, file_size, service_end, vk_peer_addr, item)
    if not info:
        return ""
    return _deposit_escrow_from_quote_info(item, info)


def _finalize_escrow_if_needed(item: dict) -> None:
    if C.vk_escrow is None:
        return
    if not item.get("escrowPendingFinalize"):
        return
    payment_commitment = str(item.get("paymentCommitment", "") or "")
    if not payment_commitment:
        return
    expected_total = int(item.get("escrowExpectedTotalWei", 0) or 0)
    deposited_now = int(item.get("escrowDepositWei", 0) or 0)
    remaining = expected_total - deposited_now
    if remaining <= 0:
        item["escrowPendingFinalize"] = False
        return
    pc_bytes = bytes32_from_hex(payment_commitment, "paymentCommitment")
    with TM.account_transaction_lock(C.DO), _escrow_tx_lock:
        nonce = TM.pending_nonce(C.w3, C.DO)
        gas_price = C.gas_price_wei()
        tx = C.vk_escrow.functions.finalizeEscrow(
            pc_bytes
        ).build_transaction({
            "from": C.DO,
            "value": remaining,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": gas_price,
        })
        signed = C.DO_ACCOUNT.sign_transaction(tx)
        tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt_tx = C.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        TX.log_contract_transaction(
            C,
            C.w3,
            actor_address=C.DO,
            contract_name="VKEscrow",
            function_name="finalizeEscrow",
            contract_address=C.vk_escrow.address,
            tx=tx,
            tx_hash=tx_hash,
            receipt=receipt_tx,
            payment_commitment=payment_commitment,
            finalize_value_wei=remaining,
        )
    if receipt_tx.status != 1:
        raise RuntimeError("escrow finalize transaction reverted")
    item["escrowFinalizeTx"] = tx_hash.hex()
    item["escrowFinalizeWei"] = remaining
    item["escrowPendingFinalize"] = False
    L.log(f"[escrow] finalized +{remaining} wei  pc={payment_commitment[:18]}...  tx={tx_hash.hex()[:18]}...")


def _vk_address_from_peer(peer: str) -> str:
    """Best-effort: return the VK Ethereum address for a given peer multiaddr.
    Used only for price verification against VaultKeeperRegistry — failure is safe."""
    try:
        return _resolve_vk_address(peer)
    except Exception:
        return ""


def _minimum_vk_stake_wei() -> int:
    try:
        if C.vault_keeper_registry is not None:
            value = int(C.vault_keeper_registry.functions.minimumVaultKeeperStake().call())
            return value
    except Exception as exc:
        pass
    try:
        return int(getattr(C.config, "MIN_GUARDIAN_STAKE_WEI", 0) or 0)
    except Exception:
        return 0


def store_shares_in_vaultmesh(
    shares_dir: str,
    file_id_hex: str,
    peers: list[str],
    json_output: str | None = None,
    service_end: int = 0,
    file_format: str = "",
    upload_instance_id: str = "",
    private_json_output: str | None = None,
    vk_addresses_by_peer: dict[str, str] | None = None,
) -> dict:
    file_id_hex = HX.normalize_file_id(file_id_hex)
    upload_instance_id = str(upload_instance_id or "").strip().lower()
    if not upload_instance_id:
        raise RuntimeError("uploadInstanceId is required for a VaultMesh upload")
    chain_id = int(C.w3.eth.chain_id)
    if C.file_registration_sc is None:
        raise RuntimeError("FileRegistrationSC is required for VaultMesh storage")
    file_registration_contract = str(C.file_registration_sc.address)
    chain_namespace = {
        "chainId": chain_id,
        "fileRegistrationContract": file_registration_contract.lower(),
    }
    PJ.ensure_recovered(C.BASE_DIR)
    if not os.path.isdir(shares_dir):
        raise RuntimeError(f"{shares_dir} is not a directory")

    if not peers:
        raise RuntimeError("No Vault Keeper peer selected")

    expected_addresses: dict[str, str] = {}
    for route, address in (vk_addresses_by_peer or {}).items():
        peer_id = peer_id_from_peer(route)
        if not peer_id:
            raise RuntimeError(
                "selected Vault Keeper address mapping has an empty peerId"
            )
        try:
            normalized = HX.prefixed_hex(
                address, expected_bytes=20, field="selected VK address"
            )
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        previous = expected_addresses.get(peer_id)
        if previous and previous.lower() != normalized.lower():
            raise RuntimeError(
                f"selected Vault Keeper peer {peer_id} maps to multiple addresses"
            )
        expected_addresses[peer_id] = normalized

    def _expected_vk_address(peer: str) -> str:
        return (
            expected_addresses.get(peer_id_from_peer(peer), "")
            or _vk_address_from_peer(peer)
        )

    active_peers = []
    min_vk_stake = _minimum_vk_stake_wei()
    for peer in peers:
        vk_addr = _expected_vk_address(peer)
        if vk_addr and C.vault_keeper_registry is not None:
            try:
                vk = C.vault_keeper_registry.functions.getVaultKeeper(
                    C.w3.to_checksum_address(vk_addr)
                ).call()
                if not bool(vk[3]):
                    L.log(f"[store] skipping inactive VK {vk_addr} ({peer_id_from_peer(peer)})")
                    continue
                stake_wei = int(vk[2])
                suspended_until = int(vk[6])
                import time as _time
                if suspended_until and suspended_until > int(_time.time()):
                    L.log(f"[store] skipping suspended VK {vk_addr} ({peer_id_from_peer(peer)})")
                    continue
                if stake_wei < min_vk_stake:
                    L.log(
                        f"[store] skipping under-staked VK {vk_addr} "
                        f"stake={stake_wei} min={min_vk_stake} ({peer_id_from_peer(peer)})"
                    )
                    continue
            except Exception as exc:
                L.log(f"[store] skipping VK with unverifiable eligibility {peer_id_from_peer(peer)}: {exc}")
                continue
        active_peers.append(peer)
    if not active_peers:
        raise RuntimeError("All selected Vault Keepers are inactive, suspended, under-staked, or unavailable")
    peers = active_peers

    files = sorted(
        f for f in os.listdir(shares_dir)
        if os.path.isfile(os.path.join(shares_dir, f))
    )

    if not files:
        raise RuntimeError("No files found in shares directory")

    manifest = {
        "storage": "vaultmesh",
        "fileId": file_id_hex,
        "uploadInstanceId": upload_instance_id,
        "vkPeers": [peer_id_from_peer(peer) for peer in peers],
        "vkPeer": peer_id_from_peer(peers[0]),
        "resolvedVkPeers": peers,
        "resolvedVkPeer": peers[0],
        "assignment": "round_robin_selected_vault_keepers",
        "identifier": "pieceRoot",
        "serviceEnd": int(service_end or 0),
        "pieceFailoverEnabled": len(peers) > len(files),
        "pieceFailoverPolicy": "unassigned-spare-vks-only",
        "pieces": [],
    }
    manifest_lock = threading.Lock()

    def _persist_manifest_piece(piece_index: int, item: dict) -> None:
        """Durably retain each completed registration before sibling futures finish."""
        if not json_output and not private_json_output:
            return
        with manifest_lock:
            by_index = {
                int(piece.get("pieceIndex", 0) or 0): piece
                for piece in manifest.get("pieces", [])
                if int(piece.get("pieceIndex", 0) or 0) > 0
            }
            by_index[int(piece_index)] = item
            manifest["pieces"] = [by_index[index] for index in sorted(by_index)]
            verified_count = sum(
                1
                for piece in manifest["pieces"]
                if piece.get("fileRegFullyVerified") is True
            )
            manifest["storageVerification"] = {
                "status": "pending",
                "lifecycleState": "partial_storage",
                "storedPieces": len(manifest["pieces"]),
                "verifiedPieces": verified_count,
                "totalPieces": len(indexed_files),
            }
            if private_json_output:
                _write_json_atomic(Path(private_json_output), manifest)
            if json_output:
                _write_json_atomic(
                    Path(json_output), _public_manifest_projection(manifest)
                )

    def _piece_index_from_name(name: str) -> int | None:
        # Canonical share filenames look like "..._p3_of_5"; honor that index
        # to keep DO pieceIndex aligned with the real RIDA share index.
        patterns = (
            r"_p(\d+)_of_\d+(?:\.[^.]+)?$",
            r"(?:^|[_-])piece[_-]?(\d+)(?:$|[_-])",
            r"(?:^|[_-])part[_-]?(\d+)(?:$|[_-])",
        )
        for pat in patterns:
            m = re.search(pat, name)
            if m:
                try:
                    idx = int(m.group(1))
                    if idx > 0:
                        return idx
                except Exception:
                    continue
        return None

    parsed = []
    seen_indices: set[int] = set()
    parse_ok = True
    for fname in files:
        idx = _piece_index_from_name(fname)
        if idx is None or idx in seen_indices:
            parse_ok = False
            break
        seen_indices.add(idx)
        parsed.append((idx, fname))
    if parse_ok and len(parsed) == len(files):
        indexed_files = sorted(parsed, key=lambda item: item[0])
    elif len(files) == 1:
        # Single-share uploads are safe with implicit index 1.
        indexed_files = [(1, files[0])]
    else:
        raise RuntimeError(
            "Unable to derive stable piece indices from share filenames; "
            "aborting to prevent invalid RIDA piece ordering."
        )
    try:
        manifest["pieces"] = [
            piece
            for piece in PJ.list_pieces(
                C.BASE_DIR, file_id=file_id_hex, include_deleted=False
            )
            if str(piece.get("uploadInstanceId", "") or "").lower()
            == upload_instance_id
        ]
    except Exception as exc:
        raise XFER.TransferPending(
            f"authoritative piece journal cannot be resumed safely: {exc}"
        ) from exc

    # Build one immutable routing plan before any piece worker starts. Existing
    # obligations own their VK regardless of discovery ordering; unbound pieces
    # are then assigned only to VKs not owned by another obligated piece.
    peer_routes_by_id: dict[str, str] = {}
    for route in peers:
        peer_id = peer_id_from_peer(route)
        if not peer_id:
            raise RuntimeError("selected Vault Keeper route has no peerId")
        if peer_id in peer_routes_by_id:
            raise RuntimeError(
                f"selected Vault Keeper list contains duplicate peerId {peer_id}"
            )
        peer_routes_by_id[peer_id] = route

    logical_by_index: dict[int, dict] = {}
    for piece_index, fname in indexed_files:
        logical_by_index[piece_index] = XFER.get_or_create_logical_piece_job(
            C.BASE_DIR,
            os.path.join(shares_dir, fname),
            file_id_hex,
            piece_index,
            int(service_end or 0),
            file_format,
            upload_instance_id=upload_instance_id,
            chain_namespace=chain_namespace,
        )
    obligated_by_logical = XFER.obligated_upload_jobs_for_logicals(
        C.BASE_DIR, list(logical_by_index.values())
    )
    routing_plan: dict[int, list[str]] = {}
    obligation_owner: dict[str, int] = {}
    assigned_counts: dict[str, int] = {
        peer_id: 0 for peer_id in peer_routes_by_id
    }
    for piece_index, logical_job in logical_by_index.items():
        obligated_job = obligated_by_logical.get(
            str(logical_job.get("logicalJobId", ""))
        )
        obligated_peer_id = ""
        obligated_route = ""
        if obligated_job is not None:
            obligated_peer_id = peer_id_from_peer(
                str(obligated_job.get("peerId") or obligated_job.get("peer") or "")
            )
            obligated_route = str(obligated_job.get("peer") or "")
        elif (
            str(logical_job.get("status", "")) == "completed"
            and isinstance(logical_job.get("result"), dict)
        ):
            completed_result = logical_job["result"]
            obligated_peer_id = peer_id_from_peer(str(
                completed_result.get("peerId")
                or completed_result.get("resolvedMultiaddr")
                or logical_job.get("winningPeerId")
                or ""
            ))
            obligated_route = str(
                completed_result.get("resolvedMultiaddr") or ""
            )
        if not obligated_peer_id:
            continue
        existing_owner = obligation_owner.get(obligated_peer_id)
        if existing_owner is not None and existing_owner != piece_index:
            raise XFER.TransferPending(
                "two pieces of this file have durable obligations to the same "
                f"Vault Keeper ({obligated_peer_id})"
            )
        current_route = peer_routes_by_id.get(obligated_peer_id, "")
        route = current_route or obligated_route
        if not route:
            raise XFER.TransferPending(
                f"piece {piece_index} has an obligated VK without a resumable route"
            )
        obligation_owner[obligated_peer_id] = piece_index
        assigned_counts[obligated_peer_id] = (
            assigned_counts.get(obligated_peer_id, 0) + 1
        )
        routing_plan[piece_index] = [route]

    for piece_index, _fname in indexed_files:
        if piece_index in routing_plan:
            continue
        start = (piece_index - 1) % len(peers)
        ordered_routes = peers[start:] + peers[:start]
        free_routes = [
            route for route in ordered_routes
            if assigned_counts.get(peer_id_from_peer(route), 0) == 0
        ]
        if free_routes:
            primary = free_routes[0]
        else:
            safe_routes = [
                route for route in ordered_routes
                if peer_id_from_peer(route) not in obligation_owner
            ]
            if not safe_routes:
                raise XFER.TransferPending(
                    f"piece {piece_index} has no VK that is not already owned "
                    "by another durable piece obligation"
                )
            primary = min(
                safe_routes,
                key=lambda route: assigned_counts.get(
                    peer_id_from_peer(route), 0
                ),
            )
        primary_id = peer_id_from_peer(primary)
        assigned_counts[primary_id] = assigned_counts.get(primary_id, 0) + 1
        routing_plan[piece_index] = [primary]

    spare_peers = [
        route for route in peers
        if assigned_counts.get(peer_id_from_peer(route), 0) == 0
    ]
    for piece_index, candidates in routing_plan.items():
        if piece_index not in logical_by_index:
            raise RuntimeError("routing plan contains an unknown piece")
        if len(candidates) == 1 and not any(
            owner == piece_index for owner in obligation_owner.values()
        ):
            candidates.extend(spare_peers)

    predeposited_by_index: dict[int, dict] = {}
    quote_items: list[dict] = []
    batch_predeposit_enabled = _config_bool("DO_ESCROW_BATCH_PREDEPOSIT", False)
    if batch_predeposit_enabled:
        batch_predeposit_enabled = False
        L.log(
            "[store] DO_ESCROW_BATCH_PREDEPOSIT disabled: durable per-transfer "
            "escrow recovery is required for pause/resume safety"
        )
    if batch_predeposit_enabled and C.vk_escrow is not None and int(service_end or 0) > 0:
        for piece_index, fname in indexed_files:
            peer = routing_plan[piece_index][0]
            full_path = os.path.join(shares_dir, fname)
            escrow_item: dict = {}
            quote = _get_quote(
                peer, os.path.getsize(full_path), int(service_end or 0),
                file_id=file_id_hex, vk_address=_expected_vk_address(peer),
            )
            quote_info = None
            if quote:
                quote_info = _prepare_escrow_quote(
                    quote,
                    os.path.getsize(full_path),
                    int(service_end or 0),
                    peer,
                    escrow_item,
                    _expected_vk_address(peer),
                )
            quote_items.append({
                "pieceIndex": piece_index,
                "quoteInfo": quote_info,
                "escrow": escrow_item,
            })
        if _deposit_escrow_batch(quote_items):
            for entry in quote_items:
                if entry.get("quoteInfo"):
                    predeposited_by_index[int(entry["pieceIndex"])] = entry["escrow"]
    elif C.vk_escrow is not None and int(service_end or 0) > 0:
        L.log("[store] escrow batch predeposit disabled; using per-attempt deposit only")

    spare_claim_lock = threading.Lock()
    spare_peer_ids = {peer_id_from_peer(peer) for peer in spare_peers}
    claimed_spares: dict[str, int] = {
        peer_id_from_peer(str(
            piece.get("resolvedMultiaddr") or piece.get("peerId") or ""
        )): int(piece.get("pieceIndex", 0) or 0)
        for piece in manifest.get("pieces", [])
        if peer_id_from_peer(str(
            piece.get("resolvedMultiaddr") or piece.get("peerId") or ""
        )) in spare_peer_ids
        and int(piece.get("pieceIndex", 0) or 0) > 0
    }

    def _claim_spare(peer: str, piece_index: int) -> bool:
        peer_id = peer_id_from_peer(peer)
        if peer_id not in spare_peer_ids:
            return True
        with spare_claim_lock:
            owner = claimed_spares.get(peer_id)
            if owner is not None and owner != int(piece_index):
                return False
            claimed_spares[peer_id] = int(piece_index)
            return True

    def _release_spare(peer: str, piece_index: int) -> None:
        peer_id = peer_id_from_peer(peer)
        if peer_id not in spare_peer_ids:
            return
        with spare_claim_lock:
            if claimed_spares.get(peer_id) == int(piece_index):
                claimed_spares.pop(peer_id, None)

    def _upload_one(piece_index, fname):
        full_path = os.path.join(shares_dir, fname)
        candidates = list(routing_plan[piece_index])
        attempts: list[dict] = []
        first_error = None
        saw_transient_pending = False
        for attempt_no, peer in enumerate(candidates, start=1):
            if not _claim_spare(peer, piece_index):
                continue
            has_predeposit = (
                attempt_no == 1 and
                bool(predeposited_by_index.get(piece_index))
            )
            try:
                item = vaultmesh_store_piece(
                    full_path, peer, file_id_hex, piece_index, service_end=service_end,
                    vk_expected_address=_expected_vk_address(peer),
                    file_format=file_format,
                    predeposited_escrow=predeposited_by_index.get(piece_index) if has_predeposit else None,
                    upload_instance_id=upload_instance_id,
                    chain_id=chain_id,
                    file_registration_contract=file_registration_contract,
                )
                attempts.append({
                    "attempt": attempt_no,
                    "peerId": peer_id_from_peer(peer),
                    "resolvedMultiaddr": peer,
                    "status": "ok",
                    "usedPredepositedEscrow": has_predeposit,
                })
                item["attemptHistory"] = attempts
                item["attemptCount"] = len(attempts)
                item["retryUsed"] = len(attempts) > 1
                _persist_manifest_piece(piece_index, item)
                return piece_index, item
            except Exception as exc:
                if isinstance(exc, XFER.TransferPaused):
                    raise
                if isinstance(exc, XFER.TransferSecurityBlocked):
                    raise
                msg = str(exc)
                try:
                    failed_job = XFER.get_or_create_upload_job(
                        C.BASE_DIR, full_path, peer, file_id_hex, piece_index,
                        int(service_end or 0), file_format,
                        upload_instance_id=upload_instance_id,
                        chain_namespace=chain_namespace,
                    )
                except Exception as state_exc:
                    raise XFER.TransferPending(
                        f"piece {piece_index} durable state is ambiguous: {state_exc}"
                    ) from exc
                if str(failed_job.get("status", "")) == "blocked_security":
                    raise XFER.TransferSecurityBlocked(
                        f"piece {piece_index} is security-blocked on "
                        f"{short_peer(peer)}: "
                        + str(
                            failed_job.get("securityVerificationError")
                            or msg
                        )
                    ) from exc
                if XFER.requires_same_peer_resume(failed_job):
                    if _resolve_registration_timeout(failed_job, peer):
                        logical_job = XFER.get_or_create_logical_piece_job(
                            C.BASE_DIR, full_path, file_id_hex, piece_index,
                            int(service_end or 0), file_format,
                            upload_instance_id=upload_instance_id,
                            chain_namespace=chain_namespace,
                        )
                        if not failed_job.get("logicalSecretsRotated"):
                            XFER.rotate_logical_piece_attempt(C.BASE_DIR, logical_job)
                            XFER.update_upload_job(
                                C.BASE_DIR, failed_job, logicalSecretsRotated=True,
                            )
                        attempts.append({
                            "attempt": attempt_no,
                            "peerId": peer_id_from_peer(peer),
                            "resolvedMultiaddr": peer,
                            "status": "expired",
                            "error": msg,
                            "usedPredepositedEscrow": has_predeposit,
                        })
                        continue
                    state, commitment_hash, deadline = _registration_attempt_state(failed_job)
                    detail = f"state={state} deadline={deadline}"
                    if commitment_hash:
                        detail += f" commitmentHash={commitment_hash[:18]}..."
                    raise XFER.TransferPending(
                        f"piece {piece_index} must resume against {short_peer(peer)}; "
                        f"{detail}: {msg}"
                    ) from exc
                # The peer reservation is intentionally durable so parallel
                # workers cannot create two obligations. Release it only after
                # the transfer manager proves that escrow was not deposited,
                # the client was never launched, and no byte/response can
                # exist at this VK.
                XFER.cancel_upload_job_before_obligation(
                    C.BASE_DIR,
                    failed_job,
                    reason=msg,
                )
                _release_spare(peer, piece_index)
                is_pending = isinstance(exc, XFER.TransferPending)
                saw_transient_pending = saw_transient_pending or is_pending
                attempts.append({
                    "attempt": attempt_no,
                    "peerId": peer_id_from_peer(peer),
                    "resolvedMultiaddr": peer,
                    "status": "pending" if is_pending else "failed",
                    "error": msg,
                    "usedPredepositedEscrow": has_predeposit,
                })
                if first_error is None:
                    first_error = msg
                L.log(
                    f"[store] piece {piece_index} attempt {attempt_no}/{len(candidates)} "
                    f"failed on {short_peer(peer)}: {msg}"
                )

        detail = "; ".join(
            f"{a['peerId']}: {a.get('error', 'failed')}" for a in attempts
        )
        if saw_transient_pending:
            raise XFER.TransferPending(
                f"piece {piece_index} is waiting for VK admission after trying "
                f"{len(candidates)} selected VKs; attempts={detail}"
            )
        raise RuntimeError(
            f"piece {piece_index} failed on all {len(candidates)} selected VKs; "
            f"firstError={first_error or 'unknown'}; attempts={detail}"
        )

    pieces_by_index = {}
    max_uploads = max(1, int(getattr(C.config, "MAX_PARALLEL_PIECE_UPLOADS", 4)))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_uploads, len(indexed_files))
    ) as executor:
        future_to_idx = {
            executor.submit(_upload_one, idx, fname): idx
            for idx, fname in indexed_files
        }
        for future in concurrent.futures.as_completed(future_to_idx):
            piece_index, item = future.result()
            pieces_by_index[piece_index] = item
            # Every piece that lands moves the bar. This is the one place that
            # knows a piece is really stored on a keeper rather than merely
            # requested, so it is the honest place to count from.
            PROG.step("pieces stored", len(pieces_by_index), len(indexed_files))
            L.log(f"piece {piece_index}/{len(indexed_files)} stored: "
                  f"{item['name']} pieceRoot={item['pieceRoot'][:22]}...")

    manifest["pieces"] = [pieces_by_index[i] for i in sorted(pieces_by_index)]
    actual_service_ends = [
        int(item.get("serviceEnd", 0) or 0) for item in manifest["pieces"]
        if int(item.get("serviceEnd", 0) or 0) > 0
    ]
    if actual_service_ends:
        manifest["serviceEnd"] = min(actual_service_ends)

    verified_count = sum(
        1 for item in manifest["pieces"] if item.get("fileRegFullyVerified") is True
    )
    manifest["storageVerification"] = {
        "status": "verified" if verified_count == len(manifest["pieces"]) else "pending",
        "lifecycleState": (
            "fully_verified"
            if verified_count == len(manifest["pieces"])
            else "verification_pending"
        ),
        "storedPieces": len(manifest["pieces"]),
        "verifiedPieces": verified_count,
        "totalPieces": len(manifest["pieces"]),
    }

    # Every expected piece returned successfully.  The wider file workflow may
    # still need DataVault/policy finalization, so this is deliberately not the
    # terminal "completed" state used by the load-test registry.
    PJ.mark_file_upload_state(
        C.BASE_DIR,
        file_id_hex,
        "storage_complete",
        upload_instance_id=upload_instance_id,
    )

    if private_json_output:
        _write_json_atomic(Path(private_json_output), manifest)
    if json_output:
        _write_json_atomic(Path(json_output), _public_manifest_projection(manifest))
        for item in manifest["pieces"]:
            if item.get("fileRegFullyVerified") is not True:
                queue_storage_verification(item, json_output)

    return manifest


def short_peer(peer: str) -> str:
    peer = str(peer)
    if "/p2p/" in peer:
        pid = peer.rsplit("/p2p/", 1)[-1]
        if len(pid) > 16:
            return pid[:8] + "..." + pid[-6:]
    if len(peer) > 28:
        return peer[:14] + "..." + peer[-10:]
    return peer


def load_vaultmesh_payloads(cids_json_path: str) -> list[dict]:
    with open(cids_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and isinstance(data.get("pieces"), list):
        pieces = []
        default_peers = data.get("vkPeers") or []
        default_peer = data.get("vkPeer", "") or (default_peers[0] if default_peers else "")
        for pos, item in enumerate(data["pieces"], start=1):
            piece_root = item.get("pieceRoot") or item.get("pieceId") or item.get("cid")
            peer = peer_id_from_peer(item.get("peerId") or item.get("vkPeer") or default_peer)
            if not piece_root:
                raise ValueError(f"Missing pieceRoot for piece at position {pos}")
            if not peer:
                raise ValueError(f"Missing peerId for piece at position {pos}")
            piece_index = int(item.get("pieceIndex", pos))
            payload = {
                "storage": "vaultmesh",
                "identifier": "pieceRoot",
                "pieceRoot": piece_root,
                "peerId": peer,
                "pieceIndex": piece_index,
                "name": item.get("name", ""),
                "size": int(item.get("size", 0)),
                "rootAlg": item.get("rootAlg", "merkle-sha256-v1"),
            }
            pieces.append(
                {
                    "label": item.get("name", f"piece_{piece_index}"),
                    "pieceIndex": piece_index,
                    "payload": payload,
                }
            )
        return pieces

    if isinstance(data, dict):
        peer = peer_id_from_peer(get_vk_peer_from_gui(show_error=False) or "")
        pieces = []
        for pos, (label, piece_root) in enumerate(data.items(), start=1):
            if not isinstance(piece_root, str):
                continue
            pieces.append(
                {
                    "label": label,
                    "pieceIndex": pos,
                    "payload": {
                        "storage": "vaultmesh",
                        "identifier": "pieceRoot",
                        "pieceRoot": piece_root,
                        "peerId": peer,
                        "pieceIndex": pos,
                        "name": label,
                    },
                }
            )
        return pieces

    raise ValueError("Unsupported share_cids.json format")
