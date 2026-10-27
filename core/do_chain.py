# do_chain.py — blockchain interactions, DKG, policy chain operations.

import os
import json
import datetime
import struct
import hashlib
import time
import itertools
from pathlib import Path
from typing import Tuple, List

from . import do_config as C
from . import do_state as S
from . import do_log as L
from . import do_records as R
from . import do_txlog as TX
from . import do_tx_manager as TM
from . import do_hex as HX
from .do_crypto import (
    is_on_curve, point_add, scalar_mult, get_finalized_v2_public_key,
    baby_is_on_curve, baby_add, baby_mul, v2_lagrange_coeff,
    v2_batch_encryption_secret, v2_encrypt_with_shared,
    telg_encrypt_str_ec, telg_v2_encrypt_str,
)

from web3 import Web3


def _require_legacy_dkg_writer():
    if getattr(C, "DKG_ATTEMPT_PROTOCOL", 0) == 1:
        raise RuntimeError("This DKG operation must use its approved recovery journal and spending limits")


def latest_chain_timestamp() -> int:
    """Return the authoritative timestamp used by FileTrust contracts."""
    if C.w3 is None:
        raise RuntimeError("blockchain connection is unavailable")
    latest = C.w3.eth.get_block("latest")
    timestamp = int(latest["timestamp"])
    if timestamp <= 0:
        raise RuntimeError("blockchain returned an invalid latest-block timestamp")
    return timestamp


def _broadcast_and_wait_signed(raw_transaction, *, timeout: int = 120):
    """Submit once and reconcile by its locally known hash if the reply is lost."""
    local_hash = C.w3.keccak(raw_transaction)
    try:
        returned_hash = C.w3.eth.send_raw_transaction(raw_transaction)
    except Exception as send_error:
        try:
            receipt = C.w3.eth.wait_for_transaction_receipt(
                local_hash, timeout=min(30, max(1, int(timeout))), poll_latency=1
            )
            return local_hash, receipt
        except Exception:
            raise send_error
    receipt = C.w3.eth.wait_for_transaction_receipt(
        returned_hash, timeout=max(1, int(timeout)), poll_latency=1
    )
    return returned_hash, receipt


def v2_dkg_deadline_state(file_id: bytes) -> dict:
    """Read one V2 DKG request deadline entirely from authoritative chain state."""
    if C.coordinator_v2 is None:
        raise RuntimeError("ZKDKG_V2 coordinator is not configured")
    requested_at = int(C.acl.functions.getKeyGenRequestedAtForFile(file_id).call())
    deadline_seconds = int(C.coordinator_v2.functions.dkgKeyGenDeadline().call())
    chain_now = latest_chain_timestamp()
    expires_at = requested_at + deadline_seconds if requested_at > 0 else 0
    return {
        "requested_at": requested_at,
        "deadline_seconds": deadline_seconds,
        "expires_at": expires_at,
        "chain_now": chain_now,
        "expired": bool(requested_at > 0 and chain_now > expires_at),
    }


def _pack_receipt_for_hashing(r: dict) -> bytes:
    """Pack receipt fields in the same order as receipt.go packReceiptForHashing.

    Packing layout (must match Solidity _computeReceiptDigest):
      uint16  receiptVersion          2 bytes
      bytes32 receiptNonce           32 bytes
      address vkAddress              20 bytes
      bytes32 pieceRoot              32 bytes
      uint64  pieceSize               8 bytes
      bytes32 keccak256(sectorId)    32 bytes
      bytes32 sectorRoot             32 bytes
      uint8   deadlineIndex           1 byte
      uint8   partitionIndex          1 byte
      bytes32 partitionRoot          32 bytes
      uint64  serviceEnd              8 bytes
      uint64  timestamp               8 bytes
      uint64  chainId                 8 bytes
      address storageProofContract   20 bytes
    """

    def hex_to_bytes32(h: str, field: str) -> bytes:
        return HX.hex_to_bytes_or_zero(h, size=32, field=field)

    def addr_to_bytes20(a: str, field: str) -> bytes:
        return HX.hex_to_bytes_or_zero(a, size=20, field=field)

    buf = b""
    buf += struct.pack(">H", int(r.get("receiptVersion", 1)))
    buf += hex_to_bytes32(r.get("receiptNonce", ""), "receiptNonce")
    buf += addr_to_bytes20(r.get("vkAddress", ""), "vkAddress")
    buf += hex_to_bytes32(r.get("pieceRoot", ""), "pieceRoot")
    buf += struct.pack(">Q", int(r.get("pieceSize", 0)))
    sector_id_bytes = r.get("sectorId", "").encode("utf-8")
    buf += Web3.keccak(sector_id_bytes)
    buf += hex_to_bytes32(r.get("sectorRoot", ""), "sectorRoot")
    buf += struct.pack(">B", int(r.get("deadlineIndex", 0)))
    buf += struct.pack(">B", int(r.get("partitionIndex", 0)))
    buf += hex_to_bytes32(r.get("partitionRoot", ""), "partitionRoot")
    buf += struct.pack(">Q", int(r.get("serviceEnd", 0)))
    buf += struct.pack(">Q", int(r.get("timestamp", 0)))
    buf += struct.pack(">Q", int(r.get("chainId", 0)))
    buf += addr_to_bytes20(r.get("storageProofContract", ""), "storageProofContract")
    return buf


def _compute_receipt_digest(r: dict) -> bytes:
    """Return keccak256 of the packed receipt fields (32-byte raw hash)."""
    return Web3.keccak(primitive=_pack_receipt_for_hashing(r))


def verify_vk_receipt(
    receipt: dict,
    expected_piece_root: str,
    expected_vk_address: str,
    chain_id: int,
    storage_proof_contract: str,
) -> tuple[bool, str]:
    """Verify a PrivateReceiptV1 returned by VK. Returns (ok, reason)."""
    if not receipt:
        return False, "receipt is empty"

    if int(receipt.get("receiptVersion", 0)) != 1:
        return False, f"unsupported receipt version {receipt.get('receiptVersion')}"

    try:
        pr = HX.normalize_hex(
            receipt.get("pieceRoot", ""), expected_bytes=32, field="receipt pieceRoot"
        )
        exp_pr = HX.normalize_hex(
            expected_piece_root, expected_bytes=32, field="expected pieceRoot"
        )
    except ValueError as exc:
        return False, f"invalid pieceRoot: {exc}"
    if pr != exp_pr:
        return False, f"pieceRoot mismatch: receipt={pr[:16]}... expected={exp_pr[:16]}..."

    try:
        vk_in_receipt = HX.normalize_hex(
            receipt.get("vkAddress", ""), expected_bytes=20, field="receipt vkAddress"
        )
        exp_vk = (
            HX.normalize_hex(
                expected_vk_address, expected_bytes=20, field="expected vkAddress"
            )
            if expected_vk_address else ""
        )
    except ValueError as exc:
        return False, f"invalid vkAddress: {exc}"
    if exp_vk and vk_in_receipt != exp_vk:
        return False, f"vkAddress mismatch: receipt=0x{vk_in_receipt} expected=0x{exp_vk}"

    if chain_id and int(receipt.get("chainId", 0)) != chain_id:
        return False, f"chainId mismatch: receipt={receipt.get('chainId')} expected={chain_id}"

    if storage_proof_contract:
        try:
            spc_receipt = HX.normalize_hex(
                receipt.get("storageProofContract", ""),
                expected_bytes=20,
                field="receipt storageProofContract",
            )
            spc_exp = HX.normalize_hex(
                storage_proof_contract,
                expected_bytes=20,
                field="expected storageProofContract",
            )
        except ValueError as exc:
            return False, f"invalid storageProofContract: {exc}"
        if spc_receipt != spc_exp:
            return False, (
                f"storageProofContract mismatch: "
                f"receipt=0x{spc_receipt} expected=0x{spc_exp}"
            )

    sig_hex = str(receipt.get("vkSignature", "")).strip()
    if not sig_hex:
        return False, "receipt has no vkSignature"

    try:
        from eth_account.messages import encode_defunct
        digest = _compute_receipt_digest(receipt)
        msg = encode_defunct(digest)
        recovered = C.w3.eth.account.recover_message(msg, signature=sig_hex)
        vk_in_receipt_cs = Web3.to_checksum_address(receipt.get("vkAddress", ""))
        if recovered.lower() != vk_in_receipt_cs.lower():
            return False, (
                f"signature verification failed: "
                f"recovered={recovered.lower()} expected={vk_in_receipt_cs.lower()}"
            )
    except Exception as exc:
        return False, f"signature verification error: {exc}"

    return True, "ok"


def _to_bytes32(h: str) -> bytes:
    return HX.hex_to_bytes(h, expected_bytes=32, field="bytes32 value")


def _named_bytes32(h: str, field: str) -> bytes:
    return HX.hex_to_bytes(h, expected_bytes=32, field=field)


def _optional_bytes32(h: str, field: str) -> bytes:
    return HX.hex_to_bytes_or_zero(h, size=32, field=field)


def _signature_bytes(signature: str) -> bytes:
    return HX.hex_to_bytes(signature, expected_bytes=65, field="VK signature")


def _record_field(record, name: str, index: int):
    try:
        return record[name]
    except Exception:
        pass
    try:
        return getattr(record, name)
    except Exception:
        pass
    return record[index]


def check_partition_linked_onchain(commitment_hash: str) -> tuple[bool, str]:
    """Read whether FileRegistrationSC.partitionLinked is true for a commitment.

    This is a read-only check. The DO deliberately does NOT send
    verifyPartitionContainsSector() itself.

    That transaction used to be signed here, with the DO's own account. Because
    its only argument points at a record that publicly names the VK, sending it
    exposed the DO-VK relationship on-chain from upload time onward — defeating
    the commitment scheme that is supposed to hide that pair until service end.

    The VK sends it now (see the VK's partition-link reconciler). Nothing is
    lost by the change: the contract verifies inclusion itself from on-chain
    partition state and accepts the call from any sender, and the VK cannot skip
    it because an unlinked record yields no current proof and therefore no
    escrow claim.

    An unlinked record is a normal pending state right after a store, not a
    failure — the caller's reconciler retries until the VK has linked it.
    """
    if C.file_registration_sc is None:
        return False, "FileRegistrationSC is not configured"
    try:
        ch_bytes = _to_bytes32(commitment_hash)
        record = C.file_registration_sc.functions.getRecord(ch_bytes).call()
        vk_addr = str(_record_field(record, "vkAddress", 2)).lower()
        if vk_addr == "0x0000000000000000000000000000000000000000":
            return False, "no on-chain record found for commitmentHash"
        if bool(_record_field(record, "partitionLinked", 7)):
            return True, "linked by VK"
        return False, "waiting for VK to link the sector to its partition"
    except Exception as exc:
        return False, f"partition link check error: {exc}"


def verify_partition_current_onchain(commitment_hash: str, receipt: dict) -> tuple[bool, str]:
    """Verify current partition linkage and proof/grace state for a stored file."""
    if C.file_registration_sc is None:
        return False, "FileRegistrationSC is not configured"
    if C.storage_proof_sc is None:
        return False, "StorageProofSC is not configured"
    try:
        ch_bytes = _to_bytes32(commitment_hash)
        record = C.file_registration_sc.functions.getRecord(ch_bytes).call()
        vk_addr = C.w3.to_checksum_address(str(_record_field(record, "vkAddress", 2)))
        if vk_addr.lower() == "0x0000000000000000000000000000000000000000":
            return False, "no on-chain record found for commitmentHash"
        deadline_index = int(_record_field(record, "deadlineIndex", 3))
        partition_index = int(_record_field(record, "partitionIndex", 4))
        sector_root = _record_field(record, "sectorRoot", 0)
        zk_piece_commitment = _record_field(record, "zkPieceCommitment", 1)

        pkey = C.storage_proof_sc.functions.partitionKeyOf(
            vk_addr, deadline_index, partition_index
        ).call()
        roots = C.storage_proof_sc.functions.getPartitionSectorRoots(pkey).call()
        pcs = C.storage_proof_sc.functions.getPartitionPieceCommitments(pkey).call()
        slot_index = None
        for idx, root in enumerate(roots):
            if bytes(root) == bytes(sector_root):
                slot_index = idx
                break
        if slot_index is None:
            return False, "registered sectorRoot is not in current partition"
        if slot_index >= len(pcs) or bytes(pcs[slot_index]) != bytes(zk_piece_commitment):
            return False, "registered zkPieceCommitment is not in current partition slot"

        proof_status = C.storage_proof_sc.functions.getPartitionProofStatus(pkey).call()
        p_vk = str(proof_status[0]).lower()
        active = bool(proof_status[1])
        registered_at = int(proof_status[3])
        if p_vk == "0x0000000000000000000000000000000000000000":
            return False, "partition never registered"
        if not active:
            return False, "partition inactive"

        try:
            version_status = C.storage_proof_sc.functions.getPartitionVersionStatus(pkey).call()
            current_content_proven = bool(version_status[3])
        except Exception as exc:
            return False, f"partition version status unavailable: {exc}"

        if current_content_proven:
            return True, "partition linked and current version proved"

        proof_period = int(C.storage_proof_sc.functions.proofPeriodSeconds().call())
        latest_ts = int(C.w3.eth.get_block("latest")["timestamp"])
        if latest_ts < registered_at + proof_period:
            return True, "partition linked; first-proof grace active"
        return False, "partition linked but current version is not proved"
    except Exception as exc:
        return False, f"partition proof verification error: {exc}"


def save_vk_receipt(receipt: dict, *, commitment_hash: str) -> str:
    """Atomically save one private receipt under its unique commitment hash."""
    receipts_dir = R.vk_receipts_dir()
    os.chmod(receipts_dir, 0o700)
    safe_commitment = HX.normalize_hex(
        commitment_hash, expected_bytes=32, field="commitmentHash"
    )
    filename = f"receipt_{safe_commitment}.json"
    path = os.path.join(receipts_dir, filename)
    tmp = path + f".{os.getpid()}.{time.time_ns()}.tmp"
    try:
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        try:
            directory_fd = os.open(receipts_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception as exc:
        L.log(f"[receipt] save error: {exc}")
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise RuntimeError("private VK receipt could not be saved durably") from exc
    return path


def submit_storage_dispute(receipt: dict, commitment_nonce: str | None = None, escrow_address: str = "") -> tuple[bool, str]:
    """Submit a storage receipt dispute on-chain using VK's signed receipt.

    The dispute names the file through the owner's commitment nonce (the argument, or the
    one saved in the receipt): StorageReceiptDispute judges it only for the file the keeper
    registered, and a deletion the owner asked for makes it invalid. Without a nonce the
    contract accepts it only when nothing was ever registered under the receipt's sector.
    A valid dispute refunds nothing by itself; the escrow is settled separately.
    Returns (ok, reason). Does not raise — caller decides whether to continue."""
    dispute = escrow_contracts(escrow_address)["storage_receipt_dispute"]
    nonce = str(commitment_nonce or receipt.get("commitmentNonce", "") or "").strip()
    if nonce:
        return submit_dispute_with_deletion_check(receipt, nonce, escrow_address=escrow_address)
    if dispute is None:
        return False, "StorageReceiptDispute not configured"

    sig_hex = str(receipt.get("vkSignature", "")).strip()
    if not sig_hex:
        return False, "receipt has no vkSignature — cannot dispute"

    try:
        receipt_version    = int(receipt.get("receiptVersion", 1))
        receipt_nonce      = _named_bytes32(receipt.get("receiptNonce", ""), "receiptNonce")
        vk_address         = C.w3.to_checksum_address(receipt.get("vkAddress", ""))
        piece_root         = _named_bytes32(receipt.get("pieceRoot", ""), "pieceRoot")
        piece_size         = int(receipt.get("pieceSize", 0))
        sector_id          = str(receipt.get("sectorId", "")).encode("utf-8")
        sector_root        = _named_bytes32(receipt.get("sectorRoot", ""), "sectorRoot")
        deadline_index     = int(receipt.get("deadlineIndex", 0))
        partition_index    = int(receipt.get("partitionIndex", 0))
        partition_root     = _optional_bytes32(receipt.get("partitionRoot", ""), "partitionRoot")
        service_end        = int(receipt.get("serviceEnd", 0))
        timestamp          = int(receipt.get("timestamp", 0))
        chain_id           = int(receipt.get("chainId", 0))
        storage_proof_addr = C.w3.to_checksum_address(receipt.get("storageProofContract", ""))
        sig_bytes          = _signature_bytes(sig_hex)

        payment_commitment_hex = str(receipt.get("paymentCommitment", "") or "")
        payment_commitment_bytes = _optional_bytes32(
            payment_commitment_hex, "paymentCommitment"
        )

        fn = dispute.functions.submitDispute(
            receipt_version,
            receipt_nonce,
            vk_address,
            piece_root,
            piece_size,
            sector_id,
            sector_root,
            deadline_index,
            partition_index,
            partition_root,
            service_end,
            timestamp,
            chain_id,
            storage_proof_addr,
            sig_bytes,
            payment_commitment_bytes,
        )
        tx_receipt = send_signed_tx_receipt(fn, C.DO_ACCOUNT, f"[dispute] submitDispute vk={vk_address[:10]}...")
        if tx_receipt.status == 1:
            L.log(f"[dispute] submitted on-chain  vk={vk_address}  tx={tx_receipt.transactionHash.hex()}")
            return True, f"dispute submitted tx={tx_receipt.transactionHash.hex()}"
        return False, f"dispute tx reverted in block {tx_receipt.blockNumber}"
    except Exception as exc:
        L.log(f"[dispute] submit failed: {exc}")
        return False, f"dispute submit error: {exc}"


def read_guardian_commitments_from_chain(file_id_bytes: bytes, key_epoch: int, n: int, t: int) -> List:
    all_commitments = []

    for i in range(1, n + 1):
        exists, guardian, Cx, Cy = C.dkg.functions.getGuardianCommitments(
            file_id_bytes,
            int(key_epoch),
            int(i),
        ).call()

        if not exists:
            raise ValueError(f"Missing Guardian commitments for SH {i}, epoch {key_epoch}")

        if len(Cx) != t or len(Cy) != t:
            raise ValueError(f"Invalid commitment length for SH {i}")

        Ci = []
        for x, y in zip(Cx, Cy):
            P = (int(x), int(y))
            if not is_on_curve(P):
                raise ValueError(f"Commitment of SH {i} is not on curve")
            Ci.append(P)

        all_commitments.append(Ci)

    return all_commitments


def aggregate_pk_from_guardian_commitments(file_id_bytes: bytes, key_epoch: int, n: int, t: int):
    commitments = read_guardian_commitments_from_chain(file_id_bytes, key_epoch, n, t)

    agg_commitments = []

    for l in range(t):
        acc = None
        for i in range(n):
            acc = point_add(acc, commitments[i][l])

        if acc is None or not is_on_curve(acc):
            raise ValueError("Invalid aggregated commitment")

        agg_commitments.append(acc)

    PK = agg_commitments[0]

    if PK is None or not is_on_curve(PK):
        raise ValueError("Invalid final PK")

    return PK, agg_commitments


def dkg_material_ready(file_id_bytes: bytes, key_epoch: int, n: int) -> bool:
    for i in range(1, n + 1):
        if not C.dkg.functions.hasGuardianCommitments(
            file_id_bytes,
            int(key_epoch),
            int(i),
        ).call():
            return False

        for j in range(1, n + 1):
            if not C.dkg.functions.hasEncryptedDkgShare(
                file_id_bytes,
                int(key_epoch),
                int(i),
                int(j),
            ).call():
                return False

    return True


def compute_pk_cache_from_chain(
    file_id_hex: str,
    key_epoch: int,
    data_owner: str,
    t_val: int,
    n_val: int,
):
    clean = R.normalize_pk_file_id(file_id_hex)
    file_id_bytes = C.w3.to_bytes(hexstr="0x" + clean)

    PK, _agg_commitments = aggregate_pk_from_guardian_commitments(
        file_id_bytes,
        int(key_epoch),
        int(n_val),
        int(t_val),
    )

    PKx, PKy = PK

    return {
        "fileId": clean,
        "dataOwner": data_owner,
        "t": int(t_val),
        "n": int(n_val),
        "PKx": str(PKx),
        "PKy": str(PKy),
        "keyEpoch": int(key_epoch),
        "source": "computed_from_onchain_guardian_commitments",
    }


def fetch_pk_from_chain(file_id_hex: str):
    clean = R.normalize_pk_file_id(file_id_hex)
    file_id_bytes = C.w3.to_bytes(hexstr="0x" + clean)

    exists, data_owner, t_val, n_val, _PKx, _PKy, key_epoch = C.dkg.functions.getKeyForFile(
        file_id_bytes
    ).call()

    if not exists or int(key_epoch) <= 0:
        return None

    if not dkg_material_ready(file_id_bytes, int(key_epoch), int(n_val)):
        return None

    return compute_pk_cache_from_chain(
        clean,
        int(key_epoch),
        data_owner,
        int(t_val),
        int(n_val),
    )


def dkg_material_progress(file_id_bytes: bytes, key_epoch: int, n: int):
    commitments = 0
    encrypted_shares = 0

    for i in range(1, int(n) + 1):
        try:
            if C.dkg.functions.hasGuardianCommitments(file_id_bytes, int(key_epoch), int(i)).call():
                commitments += 1
        except Exception:
            pass

        for j in range(1, int(n) + 1):
            try:
                if C.dkg.functions.hasEncryptedDkgShare(file_id_bytes, int(key_epoch), int(i), int(j)).call():
                    encrypted_shares += 1
            except Exception:
                pass

    return commitments, encrypted_shares, int(n), int(n) * int(n)


def compute_v2_threshold_pk_from_onchain_share_public_keys(
    file_id: bytes,
    file_id_hex: str,
    key_epoch: int,
    share_version: int,
    n: int,
    t: int,
):
    """
    Reconstruct the V2 threshold public key from public share keys stored on-chain.
    DO must never read Guardian local final-share files; those files contain each
    Guardian's secret share and remain local to the Guardian PRE nodes only.
    """
    if C.coordinator_v2 is None:
        raise RuntimeError("ZKDKG_V2 coordinator is not configured")

    shares = []
    missing = []
    for share_index in range(1, int(n) + 1):
        try:
            try:
                exists, guardian, stored_index, vkx, vky = C.coordinator_v2.functions.getV2SharePublicKeyFull(
                    file_id,
                    int(key_epoch),
                    int(share_version),
                    int(share_index),
                ).call()
            except Exception:
                exists, vkx, vky = C.coordinator_v2.functions.getV2SharePublicKey(
                    file_id,
                    int(key_epoch),
                    int(share_version),
                    int(share_index),
                ).call()
                guardian = ""
                stored_index = share_index
            if not exists:
                missing.append(share_index)
                continue
            vk = (int(vkx), int(vky))
            if not baby_is_on_curve(vk):
                raise RuntimeError(
                    f"Invalid on-chain ZKDKG_V2 public share key for shareIndex={share_index}: not on Baby Jubjub"
                )
            shares.append(
                {
                    "shareIndex": int(stored_index) or int(share_index),
                    "guardian": str(guardian),
                    "vk": vk,
                }
            )
        except RuntimeError:
            raise
        except Exception as exc:
            missing.append(share_index)
            L.log_state(
                ("do-v2-share-key-read-error", file_id_hex, key_epoch, share_index),
                str(exc),
                f"Could not read on-chain ZKDKG_V2 public share key for shareIndex={share_index}: {exc}",
            )

    if len(shares) < int(t):
        return None, len(shares), missing

    def reconstruct(selected):
        indices = [int(item["shareIndex"]) for item in selected]
        acc = None
        for item in selected:
            acc = baby_add(acc, baby_mul(v2_lagrange_coeff(int(item["shareIndex"]), indices), item["vk"]))
        return acc

    first_subset = tuple(shares[: int(t)])
    threshold_pk = reconstruct(first_subset)
    if threshold_pk is None:
        raise RuntimeError("ZKDKG_V2 threshold public key reconstruction produced infinity")

    for subset in itertools.combinations(shares, int(t)):
        candidate = reconstruct(subset)
        if candidate != threshold_pk:
            indices = [int(item["shareIndex"]) for item in subset]
            raise RuntimeError(
                "Inconsistent on-chain ZKDKG_V2 public share keys. Finalization stopped. "
                f"Threshold subset {indices} reconstructs a different public key. "
                "This usually means stale or mixed Guardian V2 DKG material was published for "
                "the same fileId/keyEpoch/shareVersion. DO is intentionally refusing to finalize. "
                "Restart with a fresh deployment/fileId/key epoch, or clear stale Guardian V2 DKG "
                "material before retrying."
            )

    return threshold_pk, len(shares), missing


@TM.serialized_account(lambda fn, account, *args, **kwargs: account.address)
def send_signed_tx_receipt(fn, account, label: str, gas_padding: int = 100_000, value: int = 0):
    fn_name = TX.function_name(fn, label)
    contract_addr = TX.contract_address(fn)
    contract_name = TX.contract_name_for_address(C, contract_addr)
    nonce = TM.pending_nonce(C.w3, account.address)
    TX.log_eth_call(
        C,
        contract_name="eth",
        function_name="getTransactionCount",
        actor_address=account.address,
        status="success",
        nonce=nonce,
        label=label,
    )
    try:
        gas_est = fn.estimate_gas({"from": account.address, "value": int(value)})
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="estimateGas",
            contract_address=contract_addr,
            actor_address=account.address,
            status="success",
            gas_estimate=gas_est,
            target_function=fn_name,
            label=label,
        )
    except Exception as exc:
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="estimateGas",
            contract_address=contract_addr,
            actor_address=account.address,
            status="failed",
            error=str(exc),
            target_function=fn_name,
            label=label,
        )
        gas_est = 1_000_000

    gas_price = C.gas_price_wei()
    TX.log_eth_call(
        C,
        contract_name="eth",
        function_name="gasPrice",
        actor_address=account.address,
        status="success",
        result=gas_price,
        label=label,
    )
    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "gas": gas_est + int(gas_padding),
            "gasPrice": gas_price,
            "value": int(value),
        }
    )
    try:
        signed = account.sign_transaction(tx)
        tx_hash, receipt = _broadcast_and_wait_signed(signed.raw_transaction)
        TX.log_contract_transaction(
            C,
            C.w3,
            actor_address=account.address,
            contract_name=contract_name,
            function_name=fn_name,
            contract_address=contract_addr,
            tx=tx,
            tx_hash=tx_hash,
            receipt=receipt,
            label=label,
        )
    except Exception as exc:
        TX.log_contract_transaction_attempt(
            C,
            actor_address=account.address,
            contract_name=contract_name,
            function_name=fn_name,
            contract_address=contract_addr,
            status="failed",
            error=str(exc),
            label=label,
        )
        raise
    L.log(f"{label}, tx: {tx_hash.hex()}, status: {receipt.status}")
    return receipt


def ensure_v2_policy_escrow(file_id: bytes) -> None:
    _require_legacy_dkg_writer()
    if C.POLICY_DKG_MODE != "ZKDKG_V2" or C.reward_manager is None:
        return
    L.set_status("Estimating DKG escrow...", "running")
    try:
        required = int(C.reward_manager.functions.estimateV2DkgEscrow(file_id).call())
        balance = int(C.reward_manager.functions.policyEscrowBalance(file_id).call())
    except Exception as exc:
        raise RuntimeError(f"Could not estimate ZKDKG_V2 service escrow: {exc}")
    if balance >= required:
        L.log(f"ZKDKG_V2 service escrow already funded: balance={balance}, required={required}")
        L.set_status("DKG escrow already funded", "done")
        return
    deposit = required - balance
    L.set_status("Depositing DKG escrow...", "running")
    L.log(f"Depositing ZKDKG_V2 DKG escrow before KeyGen: required={required}, current={balance}, deposit={deposit}")
    receipt = send_signed_tx_receipt(
        C.reward_manager.functions.depositPolicyEscrow(file_id),
        C.DO_ACCOUNT,
        "ZKDKG_V2 escrow deposit sent",
        gas_padding=80_000,
        value=deposit,
    )
    if receipt.status != 1:
        raise RuntimeError("ZKDKG_V2 escrow deposit failed")


def poll_zkdkg_v2_for_key(file_id: bytes, file_id_hex: str, owner: str, active_t: int, active_n: int) -> bool:
    if C.coordinator_v2 is None:
        L.log_state(("do-v2-dkg-no-coordinator",), True, "ZKDKG_V2 coordinator is not configured.")
        return False

    def save_finalized_v2_key() -> bool:
        (
            key_exists,
            finalized,
            data_owner,
            stored_t,
            stored_n,
            key_epoch_saved,
            share_version_saved,
            pkx_saved,
            pky_saved,
        ) = C.coordinator_v2.functions.getV2Key(file_id).call()

        if not key_exists or not finalized:
            return False

        L.set_status("Saving finalized V2 key...", "running")
        pk = (int(pkx_saved), int(pky_saved))
        if not baby_is_on_curve(pk):
            L.log_state(("do-v2-dkg-bad-pk", file_id_hex), pk, "ZKDKG_V2 finalized public key is not on Baby Jubjub.")
            return False

        S.PKX_VALUE = int(pkx_saved)
        S.PKY_VALUE = int(pky_saved)
        S.LAST_PKX_VALUE = S.PKX_VALUE
        S.LAST_PKY_VALUE = S.PKY_VALUE
        S.KEY_EPOCH = int(key_epoch_saved)
        pk_data = {
            "mode": "ZKDKG_V2",
            "curve": "BabyJubjub",
            "fileId": file_id_hex,
            "dataOwner": data_owner,
            "t": int(stored_t),
            "n": int(stored_n),
            "PKx": S.PKX_VALUE,
            "PKy": S.PKY_VALUE,
            "keyEpoch": S.KEY_EPOCH,
            "shareVersion": int(share_version_saved),
        }
        R.save_pk_cache(pk_data, write_legacy=True)
        L.log_state(
            ("do-v2-dkg-finalized", file_id_hex, S.KEY_EPOCH),
            (S.PKX_VALUE, S.PKY_VALUE),
            "=== ZKDKG_V2 KeyGen result finalized on-chain ===\n"
            f"policyId: {file_id_hex}\n"
            f"dataOwner: {data_owner}\n"
            f"guardian threshold t: {int(stored_t)}\n"
            f"guardian n: {int(stored_n)}\n"
            f"PKx: {S.PKX_VALUE}\n"
            f"PKy: {S.PKY_VALUE}\n"
            f"keyEpoch: {S.KEY_EPOCH}\n"
            f"Saved latest PK to: {R.pk_latest_path(file_id_hex)}\n"
            f"Saved epoch PK to: {R.pk_epoch_path(file_id_hex, S.KEY_EPOCH)}\n"
        )
        L.show_info("Key Generated", "ZKDKG_V2 epoch finalized on-chain and PK saved locally.")
        L.set_status("Key generated and saved", "done")
        return True

    target_epoch = 1
    try:
        (
            key_exists,
            finalized,
            data_owner,
            stored_t,
            stored_n,
            key_epoch,
            share_version,
            pkx,
            pky,
        ) = C.coordinator_v2.functions.getV2Key(file_id).call()
    except Exception as exc:
        L.log_state(("do-v2-dkg-key-read-error", file_id_hex), str(exc), f"Could not read ZKDKG_V2 key state: {exc}")
        return False

    if key_exists and int(key_epoch) > 0:
        target_epoch = int(key_epoch)

    if key_exists and finalized:
        return save_finalized_v2_key()

    _require_legacy_dkg_writer()

    try:
        material_count = int(C.coordinator_v2.functions.dealerMaterialCount(file_id, target_epoch).call())
    except Exception:
        material_count = 0

    submitted = 0
    missing = []
    for dealer_index in range(1, int(active_n) + 1):
        try:
            if C.coordinator_v2.functions.dealerMaterialSubmitted(file_id, target_epoch, dealer_index).call():
                submitted += 1
            else:
                missing.append(dealer_index)
        except Exception:
            missing.append(dealer_index)

    if submitted < int(active_n):
        L.set_status(f"Waiting for Guardian DKG material {submitted}/{int(active_n)}", "waiting")
        L.log_state(
            ("do-v2-dkg-material", file_id_hex, target_epoch),
            (submitted, int(active_n), tuple(missing)),
            f"Waiting for Guardian ZKDKG_V2 material on-chain for epoch={target_epoch}: "
            f"dealers={submitted}/{int(active_n)}, missing={missing}"
        )
        try:
            deadline_state = v2_dkg_deadline_state(file_id)
            if deadline_state["expired"]:
                if expire_dkg_keygen_onchain(file_id, file_id_hex, target_epoch):
                    L.set_status("DKG expired — escrow refunded, retry when ready", "waiting")
                    return False
        except Exception as exc:
            L.log_state(("do-v2-dkg-deadline-check-error",), str(exc), f"Could not check DKG deadline: {exc}")
        return False

    threshold_pk, onchain_share_count, missing_share_keys = compute_v2_threshold_pk_from_onchain_share_public_keys(
        file_id,
        file_id_hex,
        target_epoch,
        1,
        active_n,
        active_t,
    )
    if threshold_pk is None:
        L.set_status(f"Waiting for V2 public share keys {onchain_share_count}/{int(active_t)}", "waiting")
        L.log_state(
            ("do-v2-dkg-onchain-share-keys", file_id_hex, target_epoch),
            (onchain_share_count, int(active_t), tuple(missing_share_keys)),
            f"Waiting for on-chain ZKDKG_V2 share public keys before finalization: "
            f"{onchain_share_count}/{int(active_t)} found, missing={missing_share_keys}"
        )
        return False

    L.log_state(
        ("do-v2-dkg-finalizing", file_id_hex, target_epoch),
        threshold_pk,
        f"Finalizing ZKDKG_V2 DKG epoch={target_epoch} with Baby Jubjub threshold PK "
        "from on-chain share public keys..."
    )
    L.set_status("Finalizing V2 threshold key on-chain...", "running")
    receipt = send_signed_tx_receipt(
        C.coordinator_v2.functions.finalizeV2Dkg(
            file_id,
            int(target_epoch),
            int(threshold_pk[0]),
            int(threshold_pk[1]),
        ),
        C.DO_ACCOUNT,
        "ZKDKG_V2 finalizeDkg sent",
        gas_padding=150_000,
    )
    if receipt.status != 1:
        return False
    return save_finalized_v2_key()


def reconcile_pending_v2_dkg(
    file_id: bytes,
    file_id_hex: str,
    owner: str,
    active_t: int,
    active_n: int,
) -> dict:
    """Reconcile one durable V2 DKG request without relying on UI state.

    This function is safe for startup/background recovery.  It never uses host
    wall time and never treats an RPC error as an expired request.
    """
    _require_legacy_dkg_writer()
    if C.coordinator_v2 is None:
        raise RuntimeError("ZKDKG_V2 coordinator is not configured")
    key = C.coordinator_v2.functions.getV2Key(file_id).call()
    key_exists = bool(key[0])
    finalized = bool(key[1])
    key_epoch = int(key[5]) if key_exists and int(key[5]) > 0 else 1
    if finalized:
        pk = (int(key[7]), int(key[8]))
        if not baby_is_on_curve(pk):
            raise RuntimeError(
                f"finalized ZKDKG_V2 key is invalid for {file_id_hex}"
            )
        R.save_pk_cache(
            {
                "mode": "ZKDKG_V2",
                "curve": "BabyJubjub",
                "fileId": file_id_hex,
                "dataOwner": str(key[2] or owner),
                "t": int(key[3]),
                "n": int(key[4]),
                "PKx": pk[0],
                "PKy": pk[1],
                "keyEpoch": int(key[5]),
                "shareVersion": int(key[6]),
            },
            write_legacy=True,
        )
        return {"state": "finalized", "key_epoch": int(key[5])}

    has_request = bool(C.acl.functions.hasRequestedKeyGenForFile(file_id).call())
    if not has_request:
        return {"state": "idle", "key_epoch": key_epoch}

    deadline_state = v2_dkg_deadline_state(file_id)
    if deadline_state["expired"]:
        settled = expire_dkg_keygen_onchain(file_id, file_id_hex, key_epoch)
        return {
            "state": "expired" if settled else "expiry_pending",
            "key_epoch": key_epoch,
            **deadline_state,
        }

    missing_dealers = []
    for dealer_index in range(1, int(active_n) + 1):
        if not C.coordinator_v2.functions.dealerMaterialSubmitted(
            file_id, key_epoch, dealer_index
        ).call():
            missing_dealers.append(dealer_index)
    if missing_dealers:
        return {
            "state": "waiting_material",
            "key_epoch": key_epoch,
            "missing_dealers": missing_dealers,
            **deadline_state,
        }

    threshold_pk, share_count, missing_share_keys = (
        compute_v2_threshold_pk_from_onchain_share_public_keys(
            file_id, file_id_hex, key_epoch, 1, active_n, active_t
        )
    )
    if threshold_pk is None:
        return {
            "state": "waiting_share_keys",
            "key_epoch": key_epoch,
            "share_count": share_count,
            "missing_share_keys": missing_share_keys,
            **deadline_state,
        }

    receipt = send_signed_tx_receipt(
        C.coordinator_v2.functions.finalizeV2Dkg(
            file_id, key_epoch, int(threshold_pk[0]), int(threshold_pk[1])
        ),
        C.DO_ACCOUNT,
        f"reconcile ZKDKG_V2 finalize {file_id_hex[:18]}",
        gas_padding=150_000,
    )
    if int(receipt.status) != 1:
        raise RuntimeError(f"ZKDKG_V2 reconciliation finalization failed for {file_id_hex}")
    return reconcile_pending_v2_dkg(
        file_id, file_id_hex, owner, active_t, active_n
    )


def reconcile_known_v2_dkg_requests(
    *,
    skip_file_id_hex: str = "",
) -> list[dict]:
    """Reconcile every locally known pending V2 policy for this DO."""
    _require_legacy_dkg_writer()
    results: list[dict] = []
    skip_normalized = HX.strip_hex_prefix(skip_file_id_hex).lower()
    for policy in R.load_policies_record().values():
        file_id_hex = str(policy.get("policyId", "") or "")
        normalized = HX.strip_hex_prefix(file_id_hex).lower()
        if len(normalized) != 64 or normalized == skip_normalized:
            continue
        try:
            file_id = bytes.fromhex(normalized)
            exists, active, owner, threshold, guardians = (
                C.acl.functions.getFilePolicy(file_id).call()
            )
            if not exists or not active or str(owner).lower() != str(C.DO).lower():
                continue
            if not C.acl.functions.hasRequestedKeyGenForFile(file_id).call():
                continue
            outcome = reconcile_pending_v2_dkg(
                file_id,
                "0x" + normalized,
                str(owner),
                int(threshold),
                len(guardians),
            )
            results.append({"file_id_hex": "0x" + normalized, **outcome})
        except Exception as exc:
            results.append({
                "file_id_hex": "0x" + normalized,
                "state": "rpc_or_reconciliation_error",
                "error": str(exc),
            })
    return results


@TM.serialized_account(lambda fn, account, *args, **kwargs: account.address)
def send_signed_tx(fn, account, label: str):
    fn_name = TX.function_name(fn, label)
    contract_addr = TX.contract_address(fn)
    contract_name = TX.contract_name_for_address(C, contract_addr)
    nonce = TM.pending_nonce(C.w3, account.address)
    TX.log_eth_call(
        C,
        contract_name="eth",
        function_name="getTransactionCount",
        actor_address=account.address,
        status="success",
        nonce=nonce,
        label=label,
    )

    try:
        gas_est = fn.estimate_gas({"from": account.address})
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="estimateGas",
            contract_address=contract_addr,
            actor_address=account.address,
            status="success",
            gas_estimate=gas_est,
            target_function=fn_name,
            label=label,
        )
    except Exception as exc:
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="estimateGas",
            contract_address=contract_addr,
            actor_address=account.address,
            status="failed",
            error=str(exc),
            target_function=fn_name,
            label=label,
        )
        gas_est = 800_000

    gas_price = C.gas_price_wei()
    TX.log_eth_call(
        C,
        contract_name="eth",
        function_name="gasPrice",
        actor_address=account.address,
        status="success",
        result=gas_price,
        label=label,
    )
    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "gas": gas_est + 80_000,
            "gasPrice": gas_price,
        }
    )

    try:
        signed = account.sign_transaction(tx)
        tx_hash, receipt = _broadcast_and_wait_signed(signed.raw_transaction)
        TX.log_contract_transaction(
            C,
            C.w3,
            actor_address=account.address,
            contract_name=contract_name,
            function_name=fn_name,
            contract_address=contract_addr,
            tx=tx,
            tx_hash=tx_hash,
            receipt=receipt,
            label=label,
        )
    except Exception as exc:
        TX.log_contract_transaction_attempt(
            C,
            actor_address=account.address,
            contract_name=contract_name,
            function_name=fn_name,
            contract_address=contract_addr,
            status="failed",
            error=str(exc),
            label=label,
        )
        raise

    L.log(f"{label}, tx: {tx_hash.hex()}, status: {receipt.status}")

    if receipt.status != 1:
        raise RuntimeError(f"{label} failed")

    return receipt, tx_hash


def expire_dkg_keygen_onchain(file_id: bytes, file_id_hex: str, key_epoch: int) -> bool:
    _require_legacy_dkg_writer()
    if C.coordinator_v2 is None:
        L.log("[DKG] ZKDKG_V2 coordinator not configured — cannot expire DKG keygen.")
        return False
    fn = C.coordinator_v2.functions.expireDkgKeyGen(file_id, int(key_epoch))
    try:
        fn.estimate_gas({"from": C.DO_ACCOUNT.address})
    except Exception as e:
        msg = str(e)
        if "deadline not passed" in msg:
            L.log(f"[DKG] expireDkgKeyGen: deadline not yet passed for {file_id_hex}")
            return False
        if "no pending keygen" in msg or "no timestamp" in msg:
            L.log(f"[DKG] expireDkgKeyGen: no pending keygen for {file_id_hex}")
            return False
        L.log(f"[DKG] expireDkgKeyGen gas estimate failed for {file_id_hex}: {e}")
        return False
    receipt = send_signed_tx_receipt(fn, C.DO_ACCOUNT, f"expireDkgKeyGen {file_id_hex[:18]}", gas_padding=150_000)
    if receipt.status == 1:
        L.log(f"[DKG] KeyGen expired for {file_id_hex}, keyEpoch={key_epoch}. Escrow refunded and compensation received.")
        return True
    return False


def settle_v2_refresh_onchain(file_id: bytes, file_id_hex: str, key_epoch: int, share_version: int) -> bool:
    _require_legacy_dkg_writer()
    if C.coordinator_v2 is None:
        L.log("[DKG] ZKDKG_V2 coordinator not configured — cannot settle V2 refresh.")
        return False
    fn = C.coordinator_v2.functions.settleV2Refresh(file_id, int(key_epoch), int(share_version))
    try:
        fn.estimate_gas({"from": C.DO_ACCOUNT.address})
    except Exception as e:
        msg = str(e)
        if "deadline not passed" in msg:
            L.log(f"[DKG] settleV2Refresh: deadline not yet passed for {file_id_hex}")
            return False
        if "already settled" in msg:
            L.log(f"[DKG] settleV2Refresh: already settled for {file_id_hex}")
            return True
        if "no refresh" in msg or "no refresh timestamp" in msg:
            L.log(f"[DKG] settleV2Refresh: no pending refresh for {file_id_hex}")
            return False
        L.log(f"[DKG] settleV2Refresh gas estimate failed for {file_id_hex}: {e}")
        return False
    receipt = send_signed_tx_receipt(fn, C.DO_ACCOUNT, f"settleV2Refresh {file_id_hex[:18]}", gas_padding=150_000)
    if receipt.status == 1:
        L.log(f"[DKG] V2 refresh settled for {file_id_hex}, keyEpoch={key_epoch}, shareVersion={share_version}. Escrow refunded and compensation received.")
        return True
    return False


def check_policy_service_period(file_id: bytes, duration_days: int) -> bool:
    """Validate an initial term without sending; return True if already recorded."""
    if C.guardian_share_proof is None:
        raise RuntimeError(
            "GuardianShareProof is not configured; V2 policy service period cannot be verified"
        )
    requested_days = int(duration_days)
    if requested_days <= 0:
        raise RuntimeError("Guardian service period must be greater than zero days")
    exists, _service_start, _service_end, existing_days = (
        C.guardian_share_proof.functions.getPolicyServicePeriod(file_id).call()
    )
    if bool(exists) and int(existing_days) != requested_days:
        raise RuntimeError(
            "Guardian service period already exists with "
            f"{int(existing_days)} day(s), requested {requested_days}; "
            "refusing to reset the agreed service term. Use Guardian service renewal "
            "for extra days, or a new policy for a new agreement."
        )
    return bool(exists)


def register_policy_service_period(
    file_id: bytes,
    duration_days: int,
    *,
    allow_replace: bool = False,
) -> None:
    """Ensure the Guardian service period exists exactly once for this policy.

    This method is intentionally idempotent because policy creation and service
    period registration are separate transactions. A caller may lose the RPC
    response after either transaction and must be able to resume safely.

    allow_replace remains accepted for older callers, but never authorizes
    replacing an existing term. Extensions use the funded renewal workflow.
    """
    requested_days = int(duration_days)
    try:
        if check_policy_service_period(file_id, requested_days):
            L.log(
                f"Guardian service period already recorded ({requested_days} day(s)); no transaction needed."
            )
            return

        L.set_status("Recording Guardian service period...", "running")
        send_signed_tx(
            C.guardian_share_proof.functions.setPolicyServicePeriod(file_id, requested_days),
            C.DO_ACCOUNT,
            "Guardian service period recorded",
        )
        exists, _service_start, _service_end, existing_days = (
            C.guardian_share_proof.functions.getPolicyServicePeriod(file_id).call()
        )
        if not bool(exists) or int(existing_days) != requested_days:
            raise RuntimeError(
                "service-period transaction returned but the expected on-chain state was not found"
            )
    except Exception as exc:
        if isinstance(exc, RuntimeError) and str(exc).startswith("Guardian service period already exists"):
            raise
        raise RuntimeError(f"Could not record Guardian service period: {exc}")


def batch_exists_onchain(data_id: str, date_str: str) -> bool:
    try:
        # Import here to avoid circular import; do_actions imports do_chain
        from . import do_actions as A
        ctx = A.get_current_file_context(show_errors=False)
        if not ctx:
            return False

        file_id, file_id_hex, _do_input, policy_name, current_data_tag, current_date_str, _ts_from_ctx = ctx

        data_id_check = (data_id or current_data_tag).strip()
        date_check = (date_str or current_date_str).strip()

        ts_check = int(
            datetime.datetime.strptime(date_check, "%Y-%m-%d")
            .replace(tzinfo=datetime.timezone.utc)
            .timestamp()
        )

        exists, batch_id = C.dv.functions.getBatchIdForFileData(
            file_id,
            data_id_check,
            ts_check
        ).call()

        if not exists or int(batch_id) == 0:
            return False

        L.log(
            f"[DO] Batch already exists for this exact policy/tag/date. "
            f"policy='{policy_name}', fileId='{file_id_hex}', "
            f"Data Tag='{data_id_check}', Date='{date_check}', "
            f"batchId={batch_id}."
        )

        L.show_info(
            "Batch Exists",
            "This exact Policy Name + Data Tag + Date already exists on-chain.\n\n"
            "Use another Data Tag or Date."
        )

        return True

    except Exception as e:
        L.log(f"[DO] Batch existence check failed. Upload stopped: {e}")
        L.show_error(
            "Batch Check Error",
            f"Could not check whether this batch already exists.\n\nUpload stopped.\n\n{e}"
        )
        return True


def load_pk_json(expected_file_id_hex: str | None = None) -> bool:
    data = None

    if expected_file_id_hex:
        clean_expected = R.normalize_pk_file_id(expected_file_id_hex)
        latest_path = R.pk_latest_path(clean_expected)

        if os.path.isfile(latest_path):
            with open(latest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = fetch_pk_from_chain(clean_expected)
            if data is None:
                return False
            R.save_pk_cache(data, write_legacy=True)
            L.log(f"[PK] Loaded DKG key from on-chain and cached for policyId={clean_expected[:16]}...")

        file_id_hex = R.normalize_pk_file_id(data.get("fileId"))

        if file_id_hex != clean_expected:
            raise ValueError("Stored DKG public key belongs to another policyId.")

    else:
        latest_path = R.pk_any_latest_path()
        if not latest_path:
            return False

        with open(latest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    S.PKX_VALUE = int(data["PKx"])
    S.PKY_VALUE = int(data["PKy"])
    S.KEY_EPOCH = int(data.get("keyEpoch", 0))
    S.ACTIVE_FILE_ID_HEX = R.normalize_pk_file_id(data.get("fileId"))

    return True


def _guardian_lists_equal(a, b) -> bool:
    if len(a) != len(b):
        return False
    return all(C.w3.to_checksum_address(x).lower() == C.w3.to_checksum_address(y).lower() for x, y in zip(a, b))


def _read_v2_share_version_guardians(file_id: bytes, key_epoch: int, share_version: int, n: int):
    """Read Guardian addresses for one V2 shareVersion from on-chain public share keys."""
    if C.coordinator_v2 is None:
        raise RuntimeError("ZKDKG_V2 coordinator contract is not configured")

    guardians = []
    for share_index in range(1, int(n) + 1):
        try:
            exists, guardian, stored_index, _vkx, _vky = C.coordinator_v2.functions.getV2SharePublicKeyFull(
                file_id,
                int(key_epoch),
                int(share_version),
                int(share_index),
            ).call()
        except Exception:
            raise RuntimeError(
                "ZKDKG_V2 coordinator does not expose getV2SharePublicKeyFull(...). "
                "Deploy the updated ZkDkgCoordinatorV2 before using Same-PK Refresh."
            )

        if not exists:
            raise RuntimeError(
                f"Missing V2 public share key for shareVersion={int(share_version)}, "
                f"shareIndex={int(share_index)}"
            )

        guardians.append(C.w3.to_checksum_address(guardian))

    return guardians


# ─── File deletion (VKEscrow + StorageReceiptDispute) ───────────────────────

def verify_deletion_onchain(commitment_hash: str) -> dict:
    """Query FileRegistrationSC on-chain to verify a deletion is registered.

    Returns a dict with:
      declared     (bool) — registerFileDeletion() was called on-chain
      confirmed    (bool) — confirmFileDeletion() was called on-chain
      confirmed_at  (int) — block.timestamp when confirmed (0 if not confirmed)
      ok           (bool) — True only when both declared AND confirmed
      error         (str) — non-empty when the call itself failed
    """
    result = {
        "declared": False, "confirmed": False, "confirmed_at": 0,
        "declared_at": 0, "grace_seconds": 0, "grace_expired": False,
        "chain_timestamp": 0, "clock_error": "", "ok": False, "error": "",
        # Carried so a summary built from this alone can still find the
        # transactions on chain; reconciliation has no keeper reply to read.
        "commitmentHash": str(commitment_hash or ""),
    }
    if C.file_registration_sc is None:
        result["error"] = "FileRegistrationSC not configured"
        return result

    try:
        ch_bytes = HX.hex_to_bytes(
            commitment_hash, expected_bytes=32, field="commitmentHash"
        )
        fr_addr = C.file_registration_sc.address
        result["declared"] = bool(TX.call(
            C,
            C.file_registration_sc.functions.isDeletionDeclared(ch_bytes),
            contract_name="FileRegistrationSC",
            contract_address=fr_addr,
            commitment_hash=commitment_hash,
        ))
        result["confirmed"] = bool(TX.call(
            C,
            C.file_registration_sc.functions.isDeletionConfirmed(ch_bytes),
            contract_name="FileRegistrationSC",
            contract_address=fr_addr,
            commitment_hash=commitment_hash,
        ))
        try:
            declared_at, grace_seconds, record_confirmed = TX.call(
                C,
                C.file_registration_sc.functions.getDeletionRecord(ch_bytes),
                contract_name="FileRegistrationSC",
                contract_address=fr_addr,
                commitment_hash=commitment_hash,
            )
            result["declared_at"] = int(declared_at or 0)
            result["grace_seconds"] = int(grace_seconds or 0)
            result["confirmed"] = bool(result["confirmed"] or record_confirmed)
            # Contract deadlines use block.timestamp.  Host time can drift and
            # must never turn an in-progress deletion into a false failure.
            try:
                latest_block = C.w3.eth.get_block("latest")
                chain_timestamp = int(latest_block["timestamp"])
                result["chain_timestamp"] = chain_timestamp
                result["grace_expired"] = bool(
                    result["declared_at"]
                    and result["grace_seconds"]
                    and chain_timestamp
                    > result["declared_at"] + result["grace_seconds"]
                )
            except Exception as clock_exc:
                result["clock_error"] = str(clock_exc)
                result["grace_expired"] = False
        except Exception:
            # Older ABI/deployments still support the two authoritative bool views.
            pass
        if result["confirmed"]:
            result["confirmed_at"] = int(TX.call(
                C,
                C.file_registration_sc.functions.getDeletionConfirmedAt(ch_bytes),
                contract_name="FileRegistrationSC",
                contract_address=fr_addr,
                commitment_hash=commitment_hash,
            ))
        result["ok"] = result["declared"] and result["confirmed"]
    except Exception as exc:
        result["error"] = str(exc)
    return result


def reconcile_deletion_onchain(commitment_hash: str) -> dict:
    """Poll authoritative deletion state after a response or transport failure."""
    try:
        attempts = max(1, int(getattr(C.config, "DO_DELETION_VERIFY_ATTEMPTS", 6)))
    except Exception:
        attempts = 6
    try:
        delay_seconds = max(
            0.0, float(getattr(C.config, "DO_DELETION_VERIFY_DELAY_SECONDS", 2.0))
        )
    except Exception:
        delay_seconds = 2.0

    status = verify_deletion_onchain(commitment_hash)
    for _attempt in range(1, attempts):
        if status.get("ok"):
            break
        if delay_seconds:
            time.sleep(delay_seconds)
        status = verify_deletion_onchain(commitment_hash)
    return status


def recent_deletion_confirmation_events() -> set[str]:
    """Return recently confirmed commitment ids; periodic views remain final authority."""
    if C.file_registration_sc is None or C.w3 is None:
        return set()
    try:
        latest = int(C.w3.eth.block_number)
        lookback = max(1, int(getattr(
            C.config, "DO_DELETION_EVENT_LOOKBACK_BLOCKS", 10_000
        )))
        rows = C.file_registration_sc.events.FileDeletionConfirmed().get_logs(
            from_block=max(0, latest - lookback), to_block=latest
        )
        return {
            HX.prefixed_hex(
                row["args"]["commitmentHash"], expected_bytes=32,
                field="FileDeletionConfirmed.commitmentHash",
            ).lower()
            for row in rows
        }
    except Exception as exc:
        L.log(f"[deletion] confirmation event scan deferred: {exc}")
        return set()


def deletion_transactions_onchain(commitment_hash: str) -> dict:
    """The transactions that declared and confirmed this deletion, from the chain.

    The keeper reports these in its reply, but that reply is written the instant
    it accepts the request -- before it has declared anything -- so the fields
    are empty exactly when a user most wants them. The events carry the same
    commitment, and a log row knows the transaction that wrote it.

    partitionTx and proofTx are the keeper's own partition and proof writes on
    other contracts; they are not visible here, and are reported by the keeper
    rather than invented.
    """
    out = {"registerTx": "", "confirmTx": "", "declaredAt": 0}
    if C.file_registration_sc is None or C.w3 is None:
        return out
    try:
        ch_bytes = HX.hex_to_bytes(
            commitment_hash, expected_bytes=32, field="commitmentHash"
        )
        latest = int(C.w3.eth.block_number)
        # Paged backwards from the head rather than over one fixed lookback.
        # This chain produces about seven blocks a second, so the configured
        # 10,000-block window is roughly twenty-four minutes of history: a
        # deletion confirmed before lunch is already invisible to it. Walking
        # back finds it wherever it is, and the usual case -- a deletion
        # confirmed moments ago -- is answered by the first page.
        page = 9_000  # Cosmos refuses ranges of 10,000 or more
        wanted = {
            "registerTx": C.file_registration_sc.events.FileDeletionDeclared(),
            "confirmTx": C.file_registration_sc.events.FileDeletionConfirmed(),
        }
        to_block = latest
        while to_block >= 0 and wanted:
            from_block = max(0, to_block - page + 1)
            for key in list(wanted):
                rows = wanted[key].get_logs(
                    argument_filters={"commitmentHash": ch_bytes},
                    from_block=from_block, to_block=to_block,
                )
                if rows:
                    row = rows[-1]  # newest, if a commitment was ever re-declared
                    out[key] = HX.prefixed_hex(
                        row["transactionHash"], expected_bytes=32,
                        field=f"{key}.transactionHash",
                    )
                    if key == "registerTx":
                        out["declaredAt"] = int(row["args"].get("declaredAt", 0) or 0)
                    del wanted[key]
            if from_block == 0:
                break
            to_block = from_block - 1
    except Exception as exc:
        L.log(f"[deletion] could not read the deletion transactions: {exc}")
    return out


def _verified_deletion_summary(chain_status: dict, response: dict | None = None) -> str:
    import datetime as _dt

    response = response or {}
    confirmed_at = int(chain_status.get("confirmed_at", 0) or 0)
    confirmed_text = (
        _dt.datetime.fromtimestamp(confirmed_at).astimezone().isoformat()
        if confirmed_at else "unknown"
    )

    # Prefer whatever the keeper reported; fill the gaps from the chain, which
    # is where these transactions are anyway. Reconciliation has no keeper reply
    # at all, and used to print four empty fields as if nothing had happened.
    found = dict(response)
    if not (found.get("registerTx") and found.get("confirmTx")):
        found = {**deletion_transactions_onchain(
            str(chain_status.get("commitmentHash", "") or response.get("commitmentHash", ""))
        ), **{k: v for k, v in response.items() if v}}

    parts = [f"deletion fully verified on-chain  confirmedAt={confirmed_text}"]
    for label in ("registerTx", "partitionTx", "proofTx", "confirmTx"):
        value = str(found.get(label, "") or "")
        if value:
            parts.append(f"{label}={value}")
    return "  ".join(parts)


def redrive_deletion_request(
    vk_peer: str, commitment_hash: str, deletion_auth_secret: str = ""
) -> dict:
    """F.1: run the VK 'delete' mode and return the STRUCTURED response dict.

    Unlike request_file_deletion (which collapses the result to an (ok, summary) pair and
    performs its own chain observation), this returns the raw VK response so the re-drive
    classifier can decide on structured fields (accepted/declared/retryable/busy/ok/error).

    On any transport/parse failure it returns an empty dict, which the classifier treats as
    retryable — never terminal. The deletion secret is passed to the VK command only; it is
    never logged or returned.
    """
    from . import do_vaultmesh as VM
    try:
        HX.normalize_hex(commitment_hash, expected_bytes=32, field="commitmentHash")
    except ValueError:
        # A malformed commitment is a caller/programming error, not a VK rejection; the
        # classifier will retry, and the durable journal keeps the obligation.
        return {}
    cmd = [
        C.VAULTMESH_CMD,
        "--mode", "delete",
        "--peer", vk_peer,
        "--commitment-hash", commitment_hash,
        # This DO implements the F.1 re-drive loop, so the VK may durably queue the
        # deletion (accepted_queued) and rely on this monitor to re-supply the secret.
        "--redrive-capable",
    ]
    if deletion_auth_secret:
        cmd.extend(["--deletion-auth-secret", deletion_auth_secret])
    # Signed fresh on every attempt: a re-drive that replayed one signature would
    # eventually be refused as stale, and the deletion would never complete.
    requester, issued_at, signature = VM.build_vaultmesh_delete_auth(commitment_hash)
    cmd.extend([
        "--delete-requester", requester,
        "--delete-issued-at", str(issued_at),
        "--delete-sig", signature,
    ])
    try:
        out = VM.run_vaultmesh_cmd(cmd)
        resp = json.loads(out)
    except Exception:
        # Transport, timeout, or malformed output -> retryable (empty dict). Never log the
        # command (it contains the secret).
        return {}
    if not isinstance(resp, dict):
        return {}
    return resp


def request_file_deletion(vk_peer: str, commitment_hash: str, deletion_auth_secret: str = "") -> tuple[bool, str]:
    """Ask VK to delete a stored piece by running the VK binary in 'delete' mode.

    The VK response is only an acceptance receipt after durable journaling and
    registerFileDeletion. Completion is learned independently from chain state.

    Returns (ok, summary_string).
    """
    from . import do_vaultmesh as VM
    try:
        HX.normalize_hex(commitment_hash, expected_bytes=32, field="commitmentHash")
    except ValueError as exc:
        return False, f"deletion rejected: {exc}"

    resp: dict = {}
    try:
        cmd = [
            C.VAULTMESH_CMD,
            "--mode", "delete",
            "--peer", vk_peer,
            "--commitment-hash", commitment_hash,
            # F.1-capable DO: the VK may durably queue (accepted_queued) and this DO's
            # durable monitor re-drives the secret-bearing request until declared.
            "--redrive-capable",
        ]
        if deletion_auth_secret:
            cmd.extend(["--deletion-auth-secret", deletion_auth_secret])
        requester, issued_at, signature = VM.build_vaultmesh_delete_auth(commitment_hash)
        cmd.extend([
            "--delete-requester", requester,
            "--delete-issued-at", str(issued_at),
            "--delete-sig", signature,
        ])
        out = VM.run_vaultmesh_cmd(cmd)
        resp = json.loads(out)
        vk_ok = bool(resp.get("ok"))
        if vk_ok and resp.get("accepted"):
            # Acceptance must be fast: perform one authoritative observation,
            # then leave confirmation/dispute timing to the durable monitor.
            chain_status = verify_deletion_onchain(commitment_hash)
            deletion_id = str(resp.get("deletionId") or commitment_hash)
            if chain_status.get("ok"):
                return True, _verified_deletion_summary(chain_status, resp)
            if chain_status.get("declared"):
                return False, (
                    f"deletion pending: accepted id={deletion_id}; declared on-chain; "
                    "confirmation will be monitored"
                )
            if chain_status.get("error"):
                return False, (
                    f"deletion pending: accepted id={deletion_id}; authoritative "
                    f"status temporarily unavailable: {chain_status['error']}"
                )
            return False, (
                f"deletion pending: accepted id={deletion_id}; declaration is "
                "awaiting chain observation"
            )
        if not vk_ok:
            chain_status = reconcile_deletion_onchain(commitment_hash)
            if chain_status.get("ok"):
                summary = _verified_deletion_summary(chain_status, resp)
                L.log(
                    "[deletion] VK returned an error, but deletion was already "
                    f"confirmed on-chain: {summary}"
                )
                return True, summary
            if chain_status.get("declared") and not chain_status.get("grace_expired"):
                return False, (
                    "deletion pending: declared on-chain; VK lifecycle recovery is still running"
                )
            if resp.get("pending"):
                phase = str(resp.get("phase", "") or "unknown")
                return False, (
                    f"deletion pending: VK durable lifecycle phase={phase}; "
                    "on-chain confirmation check is temporarily unavailable"
                )
            summary = f"deletion failed (VK): {resp.get('error', 'unknown error')}"
            L.log(f"[deletion] {summary}")
            return False, summary

        L.log(
            f"[deletion] VK reported success  "
            f"registerTx={resp.get('registerTx', '')}  "
            f"partitionTx={resp.get('partitionTx', '')}  "
            f"proofTx={resp.get('proofTx', '')}  "
            f"confirmTx={resp.get('confirmTx', '')}  "
            f"claimTx={resp.get('claimTx', '')}"
        )

        # ── Independent on-chain verification ────────────────────────────────
        # DO queries FileRegistrationSC directly to confirm VK's claim.
        # VK cannot forge this: only the VK wallet that called registerFileDeletion
        # and confirmFileDeletion on-chain can make these return true.
        chain_status = reconcile_deletion_onchain(commitment_hash)

        if chain_status.get("error"):
            L.log(f"[deletion] on-chain verification unavailable: {chain_status['error']}")
            summary = (
                f"VK reported deletion (txs received) but on-chain check unavailable: "
                f"{chain_status['error']}"
            )
            return False, summary

        declared = chain_status["declared"]
        confirmed = chain_status["confirmed"]

        if not declared:
            L.log("[deletion] WARNING: VK claimed deletion but on-chain isDeletionDeclared=false")
            return False, (
                "VK reported deletion but FileRegistrationSC shows no declaration on-chain. "
                "Consider submitting a deletion failure dispute."
            )

        if not confirmed:
            L.log("[deletion] deletion declared on-chain; confirmation pending")
            return False, (
                "deletion pending: declared on-chain; VK lifecycle recovery is still running"
            )

        summary = _verified_deletion_summary(chain_status, resp)
        L.log(f"[deletion] {summary}")
        return True, summary

    except Exception as exc:
        chain_status = reconcile_deletion_onchain(commitment_hash)
        if chain_status.get("ok"):
            summary = _verified_deletion_summary(chain_status, resp)
            L.log(
                "[deletion] VK response was interrupted, but deletion was "
                f"confirmed independently on-chain: {summary}"
            )
            return True, summary
        L.log(f"[deletion] request_file_deletion error: {exc}")
        if chain_status.get("error"):
            return False, (
                f"deletion pending: VK response interrupted and authoritative "
                f"on-chain verification is temporarily unavailable: {exc}; "
                f"{chain_status['error']}"
            )
        if chain_status.get("declared") and not chain_status.get("grace_expired"):
            return False, "deletion pending: declared on-chain; VK lifecycle recovery is still running"
        return False, f"deletion error: {exc}"


def _abi_input_names(contract, function_name: str) -> list[list[str]]:
    """Input names of each overload of `function_name` in the ABI loaded for `contract`.

    The app loads every contract with the ABI of its deployed version, so this tells
    which form of a function is on chain."""
    abi = getattr(contract, "abi", None)
    if not isinstance(abi, list):
        return []
    return [
        [str(i.get("name", "")) for i in entry.get("inputs", [])]
        for entry in abi
        if isinstance(entry, dict) and entry.get("type") == "function"
        and entry.get("name") == function_name
    ]


def takes_link_nonce(contract, function_name: str) -> bool:
    return any("linkNonce" in names for names in _abi_input_names(contract, function_name))


ESCROW_CONTRACTS = {"vk_escrow": "VKEscrow", "storage_receipt_dispute": "StorageReceiptDispute",
                    "storage_registration_timeout": "StorageRegistrationTimeout",
                    "file_registration_sc": "FileRegistrationSC"}
# A piece record from an app version before deployment markers: it belongs to the oldest
# deployment the app kept, because the app can only move to another deployment with a
# signed binding, and every version that has one also marks its new records.
UNRECORDED = "unrecorded"


def piece_deployment(record: dict) -> str:
    """The deployment a stored piece belongs to: its VKEscrow address, or UNRECORDED."""
    return str((record or {}).get("vkEscrowContract", "") or "") or UNRECORDED


def escrow_contracts(escrow_address: str = "") -> dict:
    """The escrow contracts of the deployment an escrow was paid into (Phase 2.5).

    When a signed network binding moves the app to a new deployment, the settings
    client records the replaced addresses and their ABI files in deployment_history.
    An escrow paid into an earlier VKEscrow is then disputed, settled, refunded and
    reclaimed through that deployment's contracts with that deployment's ABIs. An
    escrow of the current VKEscrow, or no address, uses the current contracts; an
    address with no record keeps the Phase 2 behavior (current ABI at that address)."""
    current = {key: getattr(C, key, None) for key in ESCROW_CONTRACTS}
    escrow = current["vk_escrow"]
    try:
        history = json.loads(Path(C.config.CONFIG_PATH).read_text()).get("deployment_history") or []
    except (OSError, ValueError, AttributeError):
        history = []
    history = [entry for entry in (history if isinstance(history, list) else [])
               if isinstance(entry, dict) and isinstance(entry.get("contracts"), dict)]

    def kept(rows: dict) -> dict:
        result = dict(current)
        for key, name in ESCROW_CONTRACTS.items():
            row = rows.get(name)
            if isinstance(row, dict) and row.get("address") and row.get("json"):
                abi = json.loads(Path(row["json"]).read_text())["abi"]
                result[key] = C.w3.eth.contract(address=C.w3.to_checksum_address(row["address"]), abi=abi)
        return result
    if escrow_address == UNRECORDED:
        return kept(history[0]["contracts"]) if history else current
    if not escrow_address or escrow is None or str(escrow_address).lower() == str(escrow.address).lower():
        return current
    for entry in reversed(history):
        rows = entry["contracts"]
        if str((rows.get("VKEscrow") or {}).get("address", "")).lower() == str(escrow_address).lower():
            return kept(rows)
    result = dict(current)
    result["vk_escrow"] = C.w3.eth.contract(address=C.w3.to_checksum_address(escrow_address), abi=escrow.abi)
    return result


def escrow_link_required() -> bool:
    """True once the deployed refund contracts take the escrow's link nonce.

    Since Phase 1D (D18/D19) the admission dispute and the registration timeout refund
    an escrow only when its link commitment opens to the quoted registration, with the
    nonce the keeper gives in its quote. A quote without one must not be paid then:
    nothing could refund it before its service end and grace are over."""
    return takes_link_nonce(
        getattr(C, "storage_registration_timeout", None), "resolveRegistrationTimeout"
    ) or takes_link_nonce(
        getattr(C, "storage_receipt_dispute", None), "submitAdmissionFailureDispute"
    )


def submit_admission_failure_dispute(
    vk_address: str,
    payment_commitment: str,
    registration_commitment: str = "",
    quoted_price_wei: int = 0,
    quote_valid_until: int = 0,
    quote_signature: str = "",
    failure_signature: str = "",
    link_nonce: str = "",
    escrow_address: str = "",
) -> tuple[bool, str]:
    """Dispute a VK that rejected a store while admission was declared open.

    A contract from Phase 1D on also takes the quote's link nonce: it refunds the
    escrow only when the escrow's link commitment opens to the quoted registration."""
    dispute = escrow_contracts(escrow_address)["storage_receipt_dispute"]
    if dispute is None:
        return False, "StorageReceiptDispute not configured"
    if not payment_commitment:
        return False, "paymentCommitment is required"
    if not vk_address:
        return False, "vk address is required"
    if not registration_commitment or int(quoted_price_wei or 0) <= 0:
        return False, "signed quote terms are required"
    if int(quote_valid_until or 0) <= 0 or not quote_signature or not failure_signature:
        return False, "signed quote validity evidence is required"
    takes_link = takes_link_nonce(dispute, "submitAdmissionFailureDispute")
    if takes_link and not link_nonce:
        return False, "the quote's link nonce is required"

    try:
        vk_checksum = C.w3.to_checksum_address(vk_address)
        payment_b = _named_bytes32(payment_commitment, "paymentCommitment")
        registration_b = (
            _named_bytes32(registration_commitment, "registrationCommitment")
            if registration_commitment
            else b"\x00" * 32
        )
        link_args = [_named_bytes32(link_nonce, "linkNonce")] if takes_link else []
        fn = dispute.functions.submitAdmissionFailureDispute(
            vk_checksum,
            payment_b,
            registration_b,
            *link_args,
            int(quoted_price_wei),
            int(quote_valid_until),
            bytes.fromhex(quote_signature[2:] if quote_signature.startswith("0x") else quote_signature),
            bytes.fromhex(failure_signature[2:] if failure_signature.startswith("0x") else failure_signature),
        )
        tx_receipt = send_signed_tx_receipt(
            fn, C.DO_ACCOUNT, f"[dispute] submitAdmissionFailureDispute vk={vk_address[:10]}..."
        )
        if tx_receipt:
            L.log(
                f"[dispute] submitAdmissionFailureDispute submitted  vk={vk_address}  "
                f"pc={payment_commitment[:18]}...  tx={tx_receipt.transactionHash.hex()}"
            )
            return True, tx_receipt.transactionHash.hex()
        return False, "transaction failed"
    except Exception as exc:
        L.log(f"[dispute] submitAdmissionFailureDispute failed: {exc}")
        return False, str(exc)


# settle_disputed_escrow's reasons start with this when no later attempt can succeed.
SETTLEMENT_FINAL = "cannot be settled"


def storage_dispute_id(receipt: dict) -> bytes:
    """StorageReceiptDispute's id of a dispute about `receipt`: keccak256(vk, receiptNonce, pieceRoot)."""
    return bytes(Web3.solidity_keccak(
        ["address", "bytes32", "bytes32"],
        [
            Web3.to_checksum_address(str(receipt.get("vkAddress", ""))),
            _named_bytes32(receipt.get("receiptNonce", ""), "receiptNonce"),
            _named_bytes32(receipt.get("pieceRoot", ""), "pieceRoot"),
        ],
    ))


def settle_disputed_escrow(
    receipt: dict,
    payment_commitment: str,
    registration_commitment: str,
    link_nonce: str,
    escrow_address: str = "",
) -> tuple[bool, str]:
    """Refund the escrow of a valid storage dispute about `receipt`.

    Since Phase 1D a valid dispute applies the penalties and moves no escrow.
    settleDisputedEscrow refunds the escrow, with the compensation, to its depositor,
    only when the escrow's link commitment opens, with the quote's link nonce, to the
    registration of the disputed file. Returns (settled, reason): an escrow already
    settled counts as settled, and a reason starting with SETTLEMENT_FINAL means no
    later attempt can succeed. Does not raise."""
    contract = escrow_contracts(escrow_address)["storage_receipt_dispute"]
    if contract is None:
        return False, "StorageReceiptDispute not configured"
    if not _abi_input_names(contract, "settleDisputedEscrow"):
        return False, "the deployed StorageReceiptDispute does not settle escrow yet"
    if not (payment_commitment and registration_commitment and link_nonce):
        return False, f"{SETTLEMENT_FINAL}: the quote's registration or link nonce is missing"
    try:
        dispute_id = storage_dispute_id(receipt)
        if contract.functions.disputedEscrowSettled(dispute_id).call():
            return True, "already settled"
        # DisputeStatus: Pending (no dispute), Valid, Invalid.
        status = int(contract.functions.disputes(dispute_id).call()[7])
        if status != 1:
            return False, f"{SETTLEMENT_FINAL}: the dispute is not valid (status {status})"
        fn = contract.functions.settleDisputedEscrow(
            dispute_id,
            _named_bytes32(payment_commitment, "paymentCommitment"),
            _named_bytes32(registration_commitment, "registrationCommitment"),
            _named_bytes32(link_nonce, "linkNonce"),
        )
        with TM.account_transaction_lock(C.DO_ACCOUNT.address):
            tx_receipt = send_signed_tx_receipt(
                fn, C.DO_ACCOUNT, f"[dispute] settleDisputedEscrow pc={payment_commitment[:18]}..."
            )
        if tx_receipt and tx_receipt.status == 1:
            L.log(
                f"[dispute] disputed escrow settled  pc={payment_commitment[:18]}...  "
                f"tx={tx_receipt.transactionHash.hex()}"
            )
            return True, tx_receipt.transactionHash.hex()
        return False, "settlement transaction failed"
    except Exception as exc:
        L.log(f"[dispute] settleDisputedEscrow failed: {exc}")
        return False, f"settlement error: {exc}"


def reclaim_escrow(payment_commitment: str, escrow_address: str = "") -> tuple[bool, str]:
    """Take back an escrow its keeper never claimed, once its service end and grace are over.

    VKEscrow refuses it during the grace, after a claim or a refund, and for a deposit
    that was never finalized; a dry run finds that out without a transaction.
    `escrow_address` names the VKEscrow version the escrow was paid into, when it is not
    the configured one: every version has the same reclaimEscrow (Phase 2).
    Returns (reclaimed, reason). Does not raise."""
    if C.vk_escrow is None:
        return False, "VKEscrow not configured"
    try:
        escrow = escrow_contracts(escrow_address)["vk_escrow"]
        fn = escrow.functions.reclaimEscrow(
            _named_bytes32(payment_commitment, "paymentCommitment")
        )
        try:
            fn.call({"from": C.DO_ACCOUNT.address})
        except Exception as exc:
            return False, f"not reclaimable: {exc}"
        with TM.account_transaction_lock(C.DO_ACCOUNT.address):
            tx_receipt = send_signed_tx_receipt(
                fn, C.DO_ACCOUNT, f"[escrow] reclaimEscrow pc={payment_commitment[:18]}..."
            )
        if tx_receipt and tx_receipt.status == 1:
            L.log(
                f"[escrow] unclaimed escrow taken back  pc={payment_commitment[:18]}...  "
                f"tx={tx_receipt.transactionHash.hex()}"
            )
            return True, tx_receipt.transactionHash.hex()
        return False, "reclaim transaction failed"
    except Exception as exc:
        L.log(f"[escrow] reclaimEscrow failed: {exc}")
        return False, f"reclaim error: {exc}"


def submit_deletion_failure_dispute(receipt: dict, commitment_nonce: str, escrow_address: str = "") -> tuple[bool, str]:
    """Dispute VK for failing to delete a piece after DO requested deletion.

    Calls StorageReceiptDispute.submitDeletionFailureDispute() on-chain.
    Returns (ok, reason).
    """
    dispute = escrow_contracts(escrow_address)["storage_receipt_dispute"]
    if dispute is None:
        return False, "StorageReceiptDispute not configured"

    sig_hex = str(receipt.get("vkSignature", "")).strip()
    if not sig_hex:
        return False, "receipt has no vkSignature — cannot dispute"

    try:
        receipt_version    = int(receipt.get("receiptVersion", 1))
        receipt_nonce      = _named_bytes32(receipt.get("receiptNonce", ""), "receiptNonce")
        vk_address         = C.w3.to_checksum_address(receipt.get("vkAddress", ""))
        piece_root         = _named_bytes32(receipt.get("pieceRoot", ""), "pieceRoot")
        piece_size         = int(receipt.get("pieceSize", 0))
        sector_id          = str(receipt.get("sectorId", "")).encode("utf-8")
        sector_root        = _named_bytes32(receipt.get("sectorRoot", ""), "sectorRoot")
        deadline_index     = int(receipt.get("deadlineIndex", 0))
        partition_index    = int(receipt.get("partitionIndex", 0))
        partition_root     = _optional_bytes32(receipt.get("partitionRoot", ""), "partitionRoot")
        service_end        = int(receipt.get("serviceEnd", 0))
        timestamp          = int(receipt.get("timestamp", 0))
        chain_id           = int(receipt.get("chainId", 0))
        storage_proof_addr = C.w3.to_checksum_address(receipt.get("storageProofContract", ""))
        sig_bytes          = _signature_bytes(sig_hex)
        commitment_nonce_b = _named_bytes32(commitment_nonce, "commitmentNonce")
        commitment_hash_b  = C.w3.keccak(piece_root + commitment_nonce_b)
        deletion_dispute_id = C.w3.solidity_keccak(
            ["string", "address", "bytes32"],
            ["delDispute", vk_address, commitment_hash_b],
        )

        def already_filed() -> bool:
            try:
                return bool(TX.call(
                    C,
                    dispute.functions.deletionDisputeFiled(
                        deletion_dispute_id
                    ),
                    contract_name="StorageReceiptDispute",
                    contract_address=dispute.address,
                    commitment_hash=HX.prefixed_hex(
                        commitment_hash_b, expected_bytes=32,
                        field="deletion commitmentHash",
                    ),
                ))
            except Exception:
                return False

        if already_filed():
            return True, "deletion dispute already filed on-chain"

        fn = dispute.functions.submitDeletionFailureDispute(
            commitment_hash_b,
            commitment_nonce_b,
            receipt_version,
            receipt_nonce,
            vk_address,
            piece_root,
            piece_size,
            sector_id,
            sector_root,
            deadline_index,
            partition_index,
            partition_root,
            service_end,
            timestamp,
            chain_id,
            storage_proof_addr,
            sig_bytes,
        )
        tx_receipt = send_signed_tx_receipt(fn, C.DO_ACCOUNT, f"[dispute] submitDeletionFailureDispute vk={vk_address[:10]}...")
        if tx_receipt.status == 1:
            L.log(f"[dispute] deletion failure dispute submitted  vk={vk_address}  tx={tx_receipt.transactionHash.hex()}")
            return True, f"dispute submitted tx={tx_receipt.transactionHash.hex()}"
        return False, f"dispute tx reverted in block {tx_receipt.blockNumber}"
    except Exception as exc:
        try:
            if "already_filed" in locals() and already_filed():
                return True, "deletion dispute observed on-chain after submit error"
        except Exception:
            pass
        L.log(f"[dispute] submitDeletionFailureDispute failed: {exc}")
        return False, f"deletion failure dispute error: {exc}"


def submit_dispute_with_deletion_check(receipt: dict, commitment_nonce: str, escrow_address: str = "") -> tuple[bool, str]:
    """Submit a storage receipt dispute with deletion-awareness.

    Calls StorageReceiptDispute.submitDisputeWithDeletionCheck() — same as
    submitDispute() but adds commitmentNonce so the contract can automatically
    resolve the dispute as Invalid when deletion has been confirmed on-chain.
    Returns (ok, reason).
    """
    dispute = escrow_contracts(escrow_address)["storage_receipt_dispute"]
    if dispute is None:
        return False, "StorageReceiptDispute not configured"

    sig_hex = str(receipt.get("vkSignature", "")).strip()
    if not sig_hex:
        return False, "receipt has no vkSignature — cannot dispute"

    try:
        receipt_version    = int(receipt.get("receiptVersion", 1))
        receipt_nonce      = _named_bytes32(receipt.get("receiptNonce", ""), "receiptNonce")
        vk_address         = C.w3.to_checksum_address(receipt.get("vkAddress", ""))
        piece_root         = _named_bytes32(receipt.get("pieceRoot", ""), "pieceRoot")
        piece_size         = int(receipt.get("pieceSize", 0))
        sector_id          = str(receipt.get("sectorId", "")).encode("utf-8")
        sector_root        = _named_bytes32(receipt.get("sectorRoot", ""), "sectorRoot")
        deadline_index     = int(receipt.get("deadlineIndex", 0))
        partition_index    = int(receipt.get("partitionIndex", 0))
        partition_root     = _optional_bytes32(receipt.get("partitionRoot", ""), "partitionRoot")
        service_end        = int(receipt.get("serviceEnd", 0))
        timestamp          = int(receipt.get("timestamp", 0))
        chain_id           = int(receipt.get("chainId", 0))
        storage_proof_addr = C.w3.to_checksum_address(receipt.get("storageProofContract", ""))
        sig_bytes          = _signature_bytes(sig_hex)

        payment_commitment_hex = str(receipt.get("paymentCommitment", "") or "")
        payment_commitment_bytes = _optional_bytes32(
            payment_commitment_hex, "paymentCommitment"
        )
        commitment_nonce_b = _named_bytes32(commitment_nonce, "commitmentNonce")

        fn = dispute.functions.submitDisputeWithDeletionCheck(
            receipt_version,
            receipt_nonce,
            vk_address,
            piece_root,
            piece_size,
            sector_id,
            sector_root,
            deadline_index,
            partition_index,
            partition_root,
            service_end,
            timestamp,
            chain_id,
            storage_proof_addr,
            sig_bytes,
            payment_commitment_bytes,
            commitment_nonce_b,
        )
        tx_receipt = send_signed_tx_receipt(fn, C.DO_ACCOUNT, f"[dispute] submitDisputeWithDeletionCheck vk={vk_address[:10]}...")
        if tx_receipt.status == 1:
            L.log(f"[dispute] submitDisputeWithDeletionCheck submitted  vk={vk_address}  tx={tx_receipt.transactionHash.hex()}")
            return True, f"dispute submitted tx={tx_receipt.transactionHash.hex()}"
        return False, f"dispute tx reverted in block {tx_receipt.blockNumber}"
    except Exception as exc:
        L.log(f"[dispute] submitDisputeWithDeletionCheck failed: {exc}")
        return False, f"dispute with deletion check error: {exc}"
