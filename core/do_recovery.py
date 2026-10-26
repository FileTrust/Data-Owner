# do_recovery.py — get a file's pieces back when the local records are gone.
#
# A Data Owner who reinstalls, or moves to another computer, arrives with a
# key and nothing else. The chain still shows the policies -- those are public
# -- but the piece addresses and the keepers holding them were only ever in
# policies.json on the old machine, because on chain they are encrypted to the
# policy's key.
#
# The way to open them already exists: it is what a requester does. So the
# owner does the same thing for its own file -- a temporary PRE keypair, an
# access request, the guardians' partials, and the same decryption -- and
# writes the result back into its own records.
#
# No contract change was needed for this, which is worth stating because it
# looked like there was. The global requestReenc() does ask for the Requester
# role, which a Data Owner can never hold; but the V2 path does not use it.
# DataVault and TElGv2 both check isRequesterForFile only, and
# addRequesterToFile lets the file's own owner add any address, itself
# included. Verified against the live chain before this was written.
#
# What comes back: the piece addresses and which keeper holds each one. The
# commitment nonce and the deletion secret are not here -- since do_secrets
# they are derived from the account key, so they need no recovery at all. The
# keeper's signed receipt is the one thing neither route returns; it has to be
# asked for from the keeper that issued it.
#
# One file at a time, on purpose. The guardians charge for each request, and a
# user with a hundred files must not be billed for ninety-nine they did not
# ask for.

from __future__ import annotations

import json
import time

from web3 import Web3

from . import do_config as C
from . import do_hex as HX
from . import do_log as L
from . import do_records as R
from . import do_tx_manager as TM
from . import do_txlog as TX
from .do_v2_crypto import (
    BABY_G,
    BABY_L,
    baby_is_on_curve,
    baby_mul,
    v2_combine_partials,
    v2_decrypt_with_shared,
    v2_elgamal_decrypt,
    xor_stream,
)

# How long to wait for the guardians. They answer in seconds on a healthy
# network; the long tail is a guardian that has to catch up on blocks.
PARTIAL_ATTEMPTS = 60
PARTIAL_DELAY_SECONDS = 5


class RecoveryError(Exception):
    """Recovery could not finish. The message is meant for the user."""


# ── the temporary requester identity ─────────────────────────────────────────

def new_access_keypair() -> dict:
    """A Baby Jubjub keypair for one recovery, kept in memory only.

    The guardians re-encrypt to this public key and only its holder can read
    the result. It is thrown away afterwards: it protects one answer, and a
    key that never reaches disk cannot be stolen from there later.
    """
    import secrets as _secrets

    x_req = _secrets.randbelow(BABY_L - 1) + 1
    public = baby_mul(x_req, BABY_G)
    if public is None:
        raise RecoveryError("could not make a recovery key")
    return {"x_req": x_req, "pk_x": int(public[0]), "pk_y": int(public[1])}


# ── the chain steps ──────────────────────────────────────────────────────────

def _file_id_bytes(file_id) -> bytes:
    return HX.hex_to_bytes(str(file_id), expected_bytes=32, field="fileId")


def owns_file(file_id) -> bool:
    exists, _active, owner, _threshold, _guardians = C.acl.functions.getFilePolicy(
        _file_id_bytes(file_id)
    ).call()
    return bool(exists) and str(owner).lower() == str(C.DO).lower()


def allow_self(file_id) -> bool:
    """Put this owner on its own file's requester list. True if a tx was sent.

    The contract takes the owner's word for its own file -- the require is
    "caller is this file's data owner" -- and the per-file list is what every
    V2 check reads.
    """
    file_id_b = _file_id_bytes(file_id)
    if C.acl.functions.isRequesterForFile(file_id_b, C.DO).call():
        return False
    if not owns_file(file_id):
        raise RecoveryError("this account does not own that policy")
    fn = C.acl.functions.addRequesterToFile(file_id_b, C.DO)
    CH_send(fn, "Recovery: allowed myself to read my own file")
    return True


def request_reencryption(file_id) -> bool:
    """Ask for re-encryption on this file. True if a tx was sent."""
    if C.acl.functions.hasRequestedReenc(C.DO).call():
        return False
    fn = C.acl.functions.requestReencForFile(_file_id_bytes(file_id))
    CH_send(fn, "Recovery: asked the guardians for re-encryption")
    return True


def CH_send(fn, label: str):
    """Send a transaction with the app's own nonce and gas handling."""
    from . import do_chain as CH

    return CH.send_signed_tx(fn, C.DO_ACCOUNT, label)


def _batch_record(file_id, batch_id: int) -> dict:
    """One upload, as the chain describes it."""
    (
        _fid, data_owner, data_id, ts, n_ida, t_ida, key_epoch, cid_indices,
    ) = C.dv.functions.getBatch(int(batch_id)).call()
    return {
        "batchId": int(batch_id),
        "dataOwner": Web3.to_checksum_address(data_owner),
        "dataId": str(data_id),
        # The sealed copies are filed under the upload id the app used. That
        # id is not on chain, but it is derived -- policy, data tag and
        # timestamp -- and all three are here, so it comes back exactly as the
        # upload wrote it.
        "uploadInstanceId": HX.derive_upload_instance_id(file_id, str(data_id), int(ts)),
        "timestamp": int(ts),
        "n": int(n_ida),
        "t": int(t_ida),
        "keyEpoch": int(key_epoch),
        "cidIndices": [int(x) for x in cid_indices],
    }


def list_batches(file_id) -> list[dict]:
    """Every upload this policy has on chain, newest first.

    The data tag, the date and the number of pieces are public: the chain
    stores them beside the encrypted addresses. So a policy's file list can be
    rebuilt for nothing, and only opening a file's piece addresses costs the
    guardians' fee. Listing the newest upload alone -- which is what this used
    to do -- made every earlier file invisible on a new install.
    """
    file_id_b = _file_id_bytes(file_id)
    try:
        count = int(C.dv.functions.batchCountByFileId(file_id_b).call())
    except Exception as exc:
        raise RecoveryError(f"the chain could not be read: {exc}") from exc

    out: list[dict] = []
    for index in range(count - 1, -1, -1):
        try:
            found, batch_id = C.dv.functions.getBatchIdForFileAt(
                file_id_b, index
            ).call()
            if not found or int(batch_id) == 0:
                continue
            out.append(_batch_record(file_id, int(batch_id)))
        except Exception as exc:
            L.log(f"[Recovery] batch {index} of this policy could not be read: {exc}")
    return out


def batch_for(file_id, batch_id: int | None = None, upload_id: str = "") -> dict:
    """The upload a recovery was asked for, named either way.

    A policy holds many files. Taking the newest and calling it "the file"
    charges the guardians' fee for something the user did not pick.
    """
    if batch_id:
        return _batch_record(file_id, int(batch_id))
    wanted = str(upload_id or "").strip().lower()
    for batch in list_batches(file_id):
        if not wanted or str(batch["uploadInstanceId"]).lower() == wanted:
            return batch
    raise RecoveryError("that file is not on chain under this policy")


def record_policy_files(file_id) -> int:
    """List this policy's uploads in the local records, with no pieces yet.

    Free: it reads what the chain publishes in the clear. The rows appear with
    their tag, date and piece count, and each one can then be opened on its
    own -- which is the point, because opening is what costs.
    """
    from . import do_records as RECORDS

    batches = list_batches(file_id)
    if not batches:
        return 0

    records = RECORDS.load_policies_record()
    known = set()
    for record in records.values():
        for existing in record.get("files", []):
            upload_id = str(existing.get("uploadInstanceId", "")).strip().lower()
            if upload_id:
                known.add(upload_id)

    added = 0
    for batch in batches:
        upload_id = str(batch["uploadInstanceId"]).lower()
        if upload_id in known:
            continue
        date_str = time.strftime("%Y-%m-%d", time.localtime(int(batch["timestamp"])))
        RECORDS.save_file_upload_record(
            "", batch["dataId"], date_str, int(batch["timestamp"]),
            # No pieces: their addresses are encrypted, and opening them is
            # what the guardians charge for. The row says how many there are.
            [{"pieceIndex": index, "uploadInstanceId": batch["uploadInstanceId"]}
             for index in range(len(batch["cidIndices"]))],
            file_id=file_id,
        )
        added += 1
    return added


def latest_batch(file_id) -> dict:
    """The most recent upload of this policy. Kept for callers that mean it."""
    file_id_b = _file_id_bytes(file_id)
    found, batch_id = C.dv.functions.getBatchIdForFile(file_id_b).call()
    if not found or int(batch_id) == 0:
        raise RecoveryError("the chain has no upload recorded for this policy")
    (
        _file_id, data_owner, data_id, ts, n_ida, t_ida, key_epoch, cid_indices,
    ) = C.dv.functions.getBatch(int(batch_id)).call()
    return {
        "batchId": int(batch_id),
        "dataOwner": Web3.to_checksum_address(data_owner),
        "dataId": str(data_id),
        # The sealed copies are filed under the upload id the app used. That
        # id is not on chain, but it is derived -- policy, data tag and
        # timestamp -- and all three are in this batch, so it comes back
        # exactly as the upload wrote it.
        "uploadInstanceId": HX.derive_upload_instance_id(file_id, str(data_id), int(ts)),
        "timestamp": int(ts),
        "n": int(n_ida),
        "t": int(t_ida),
        "keyEpoch": int(key_epoch),
        "cidIndices": [int(x) for x in cid_indices],
    }


PENDING_FILE = "recovery_pending.json"


def _pending_path(base_dir=None):
    from pathlib import Path as _Path

    return _Path(base_dir or C.BASE_DIR) / PENDING_FILE


def save_pending(file_id, request_id: int, keypair: dict, base_dir=None,
                 upload_id: str = "") -> None:
    """Keep the recovery key while its request is still unanswered.

    The key is thrown away on success, but until then it is the only thing
    that can open an answer already paid for. Without this, a recovery that
    stopped for any reason -- a closed window, a slow guardian -- had to buy
    the same answer again.

    Written 0600. It is a key, even if it is only worth one file's addresses.
    """
    import json as _json
    import os as _os
    import tempfile as _tempfile

    path = _pending_path(base_dir)
    payload = {
        "fileId": str(file_id),
        "uploadInstanceId": str(upload_id),
        "requestId": int(request_id),
        "x_req": str(keypair["x_req"]),
        "pk_x": str(keypair["pk_x"]),
        "pk_y": str(keypair["pk_y"]),
        "savedAt": int(time.time()),
    }
    fd, tmp = _tempfile.mkstemp(dir=str(path.parent), prefix=".recovery-", suffix=".json")
    try:
        with _os.fdopen(fd, "w", encoding="utf-8") as handle:
            _json.dump(payload, handle)
        _os.chmod(tmp, 0o600)
        _os.replace(tmp, path)
    except BaseException:
        try:
            _os.unlink(tmp)
        except OSError:
            pass


def load_pending(file_id, base_dir=None, upload_id: str = "") -> tuple[int, dict] | None:
    """A paid, unanswered request for this upload, if this install made one.

    Matched on the upload as well as the policy: a request bought for one file
    cannot open another, and reusing it would waste the fee and return the
    wrong answer.
    """
    try:
        data = json.loads(_pending_path(base_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    wanted = HX.strip_hex_prefix(str(file_id)).lower()
    if HX.strip_hex_prefix(str(data.get("fileId", ""))).lower() != wanted:
        return None
    if upload_id and str(data.get("uploadInstanceId", "")).lower() != str(upload_id).lower():
        return None
    try:
        return int(data["requestId"]), {
            "x_req": int(data["x_req"]),
            "pk_x": int(data["pk_x"]),
            "pk_y": int(data["pk_y"]),
        }
    except (KeyError, TypeError, ValueError):
        return None


def clear_pending(base_dir=None) -> None:
    try:
        _pending_path(base_dir).unlink()
    except OSError:
        pass


def guardian_threshold(file_id) -> int:
    """How many guardians must answer: the DKG threshold, not the IDA one.

    getBatch's `t` is how many pieces rebuild the file -- a different number
    for a different job. Waiting on it meant a recovery sat for ever while the
    guardians had already finished: they declare "threshold already met" at
    their own t and stop, and nothing more was ever coming.
    """
    if C.coordinator_v2 is None:
        raise RecoveryError("this install has no ZkDkgCoordinatorV2 address")
    (
        exists, _finalized, _owner, required_t, _n, _epoch, _share_version,
        _pkx, _pky,
    ) = C.coordinator_v2.functions.getV2Key(_file_id_bytes(file_id)).call()
    if not exists or int(required_t) <= 0:
        raise RecoveryError("this policy has no key on chain to recover with")
    return int(required_t)


def request_access(file_id, batch: dict, keypair: dict) -> int:
    """Pay the escrow and open an access request. Returns its id."""
    file_id_b = _file_id_bytes(file_id)
    if C.reward_manager is None:
        raise RecoveryError(
            "this install has no RewardManager address, so the guardians' fee "
            "cannot be worked out"
        )
    try:
        escrow = int(C.reward_manager.functions.estimateV2PreEscrow(
            file_id_b, int(batch["batchId"])
        ).call())
    except Exception as exc:
        raise RecoveryError(f"could not price the guardians' work: {exc}") from exc

    L.log(f"[Recovery] guardian escrow for this file: {escrow} wei")
    fn = C.dv.functions.requestDataAccessForFileDataWithEscrow(
        file_id_b, batch["dataId"], int(batch["timestamp"]),
        int(keypair["pk_x"]), int(keypair["pk_y"]),
    )
    receipt = CH_send_with_value(fn, escrow, "Recovery: asked for my own file's key")
    request_id = _request_id_from_receipt(receipt)
    if request_id is None:
        raise RecoveryError("the chain accepted the request but did not return its id")
    return request_id


def CH_send_with_value(fn, value_wei: int, label: str):
    """Like CH_send, but carrying the escrow the V2 path requires."""
    account = C.DO_ACCOUNT
    nonce = TM.pending_nonce(C.w3, account.address)
    gas = fn.estimate_gas({"from": account.address, "value": int(value_wei)})
    tx = fn.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": gas + 50_000,
        "gasPrice": C.gas_price_wei(),
        "value": int(value_wei),
    })
    signed = account.sign_transaction(tx)
    tx_hash = C.w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = C.w3.eth.wait_for_transaction_receipt(tx_hash)
    TX.log_contract_transaction(
        C, C.w3,
        actor_address=account.address,
        contract_name="DataVault",
        function_name="requestDataAccessForFileDataWithEscrow",
        contract_address=C.dv.address,
        tx=tx, tx_hash=tx_hash, receipt=receipt,
    )
    L.log(f"[Recovery] {label}: tx {tx_hash.hex()} status {receipt.status}")
    if int(receipt.status) != 1:
        raise RecoveryError("the access request transaction failed on chain")
    return receipt


def _request_id_from_receipt(receipt) -> int | None:
    for event_name in ("DataAccessRequestedV2", "DataAccessRequested"):
        event = getattr(C.dv.events, event_name, None)
        if event is None:
            continue
        try:
            logs = event().process_receipt(receipt, errors=__import__(
                "web3.logs", fromlist=["DISCARD"]).DISCARD)
        except Exception:
            continue
        for entry in logs:
            value = entry["args"].get("requestId")
            if value is not None:
                return int(value)
    return None


def wait_for_partials(request_id: int, required_t: int,
                      attempts: int = PARTIAL_ATTEMPTS,
                      delay: float = PARTIAL_DELAY_SECONDS,
                      on_progress=None) -> list[dict]:
    """Wait until enough guardians have answered, then return their partials."""
    telg = C.telg_v2
    if telg is None:
        raise RecoveryError("this install is not configured for the V2 key scheme")
    for attempt in range(1, attempts + 1):
        # Batch form first: it is what a multi-piece upload produces, and the
        # per-CID reader cannot tell "no answer" from "answered in the other
        # shape".
        sets = read_batch_partials(telg, request_id, required_t)
        if len(sets) >= required_t:
            return sets
        sets = read_partials(telg, request_id, required_t)
        if len(sets) >= required_t:
            return sets
        if on_progress is not None:
            on_progress(len(sets), required_t, attempt)
        time.sleep(delay)
    raise RecoveryError(
        f"only {len(sets)} of {required_t} guardians answered; try again later"
    )


def read_batch_partials(telg, request_id: int, required_t: int) -> list[dict]:
    """The one-per-request form of a guardian's answer.

    A batch upload encrypts every piece under a single C1, so a guardian
    answers once for the whole request instead of once per piece. The per-CID
    reader returns a partial with an empty piece map in that case, which looks
    like "answered but about nothing" -- and a recovery built only on the
    per-CID form fails on a file that uploaded perfectly well.
    """
    guardians = telg.functions.getV2PartialGuardians(int(request_id)).call()
    out: list[dict] = []
    seen: set[int] = set()
    failures = 0
    for guardian in guardians:
        try:
            (
                exists, share_index, _hash, e1x, e1y, e2x, e2y,
            ) = telg.functions.getV2BatchPartial(
                int(request_id), Web3.to_checksum_address(guardian)
            ).call()
        except Exception:
            # One guardian the call cannot answer for is not proof that this
            # chain has no batch partials. Treating it as proof abandoned the
            # batch form entirely, and the per-CID form then returned answers
            # about no pieces at all -- which looked like enough guardians and
            # failed at the first piece.
            failures += 1
            continue
        if not exists or int(share_index) in seen:
            continue
        seen.add(int(share_index))
        out.append({
            "guardian": Web3.to_checksum_address(guardian),
            "share_index": int(share_index),
            "E1": (int(e1x), int(e1y)),
            "E2": (int(e2x), int(e2y)),
        })
        if len(out) >= required_t:
            break
    if not out and failures and failures == len(guardians):
        return []              # this chain has no batch partials at all
    return out


def read_partials(telg, request_id: int, required_t: int) -> list[dict]:
    """The guardians' encrypted partials for this request, one set each.

    A set covering no pieces is not counted. In the batch form the per-CID
    view of the same answer exists and is empty, so counting those reached
    the threshold with nothing in them and the recovery died on the first
    piece: "not enough guardian answers for piece entry 460", after paying.
    """
    guardians = telg.functions.getV2PartialGuardians(int(request_id)).call()
    out: list[dict] = []
    seen: set[int] = set()
    for guardian in guardians:
        (
            exists, share_index, _hash, cid_indices, e1x, e1y, e2x, e2y,
        ) = telg.functions.getV2Partial(
            int(request_id), Web3.to_checksum_address(guardian)
        ).call()
        if not exists or int(share_index) in seen or len(cid_indices) == 0:
            continue
        seen.add(int(share_index))
        out.append({
            "guardian": Web3.to_checksum_address(guardian),
            "share_index": int(share_index),
            "partials": {
                int(cid): {
                    "E1": (int(e1x[i]), int(e1y[i])),
                    "E2": (int(e2x[i]), int(e2y[i])),
                }
                for i, cid in enumerate(cid_indices)
            },
        })
        if len(out) >= required_t:
            break
    return out


# ── opening what came back ───────────────────────────────────────────────────

def decrypt_pieces(batch: dict, partial_sets: list[dict], keypair: dict) -> list[dict]:
    """Turn the guardians' partials into the piece addresses they protect."""
    # The guardian threshold, never the IDA one: these are shares of the key,
    # not pieces of the file.
    required_t = int(batch.get("guardianThreshold") or 0) or len(partial_sets)
    pieces: list[dict] = []

    # One shared point for the whole request, when the guardians answered in
    # the batch form. Combined once here rather than per piece.
    batch_shared = None
    if partial_sets and "E1" in partial_sets[0]:
        points = []
        for partial in partial_sets:
            share = v2_elgamal_decrypt(partial["E1"], partial["E2"], keypair["x_req"])
            if share is None:
                continue
            points.append((int(partial["share_index"]), share))
        if len(points) < required_t:
            raise RecoveryError(
                f"only {len(points)} of {required_t} guardian answers could be opened"
            )
        batch_shared = v2_combine_partials(points[:required_t])
        if batch_shared is None:
            raise RecoveryError("the guardian answers did not combine")
    for cid_index in batch["cidIndices"]:
        c1x, c1y, c2, ct_sym = C.dv.functions.getEncCid(int(cid_index)).call()
        if not baby_is_on_curve((int(c1x), int(c1y))):
            raise RecoveryError(f"the chain's entry {cid_index} is not readable")

        if batch_shared is not None:
            shared = batch_shared
        else:
            points = []
            for partial in partial_sets:
                encrypted = partial["partials"].get(int(cid_index))
                if encrypted is None:
                    continue
                share = v2_elgamal_decrypt(
                    encrypted["E1"], encrypted["E2"], keypair["x_req"])
                if share is None:
                    continue
                points.append((int(partial["share_index"]), share))
            if len(points) < required_t:
                raise RecoveryError(
                    f"not enough guardian answers for piece entry {cid_index}"
                )
            shared = v2_combine_partials(points[:required_t])
            if shared is None:
                raise RecoveryError(
                    f"the guardian answers did not combine for {cid_index}")

        try:
            key_hex = v2_decrypt_with_shared(shared, bytes(c2)).decode("utf-8").strip()
            key = bytes.fromhex(key_hex)
        except Exception as exc:
            raise RecoveryError(f"entry {cid_index} did not decrypt: {exc}") from exc

        payload_bytes = xor_stream(bytes(ct_sym), key)
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise RecoveryError(f"entry {cid_index} is not a piece record: {exc}") from exc
        if not isinstance(payload, dict) or not payload.get("pieceRoot"):
            # The meta entry of an AES upload carries key material, not a
            # piece. It is not an error, it simply is not a piece.
            continue
        pieces.append({
            "cidIndex": int(cid_index),
            "pieceRoot": str(payload.get("pieceRoot", "")),
            "peerId": str(payload.get("peerId", "")),
        })
    return pieces


# ── the two secrets, worked out again from the account key ───────────────────
#
# A recovered piece can be listed, but not acted on: deleting it means handing
# the keeper the deletion secret, and disputing it means quoting the commitment
# nonce. Neither is on the chain, neither is in the keeper's receipt -- the
# chain holds only their hashes.
#
# Since do_secrets they are not stored at all, they are derived from the
# account key. What the derivation needs and recovery does not have is the
# piece's own number and which attempt stored it. Both are small, so every
# combination is tried until one hashes to the commitment the keeper signed.
# A match is proof: the same hash cannot come from another piece's secret.

# Retries are rare; a piece that needed more attempts than this was rotated
# far past anything the network has seen.
MAX_SECRET_ATTEMPTS = 8


def restore_derived_secrets(file_id, upload_id: str, pieces: list[dict]) -> int:
    """Put back each piece's nonce and deletion secret. Returns how many.

    Verified, never guessed: a derived nonce is only kept when it reproduces
    the commitment hash in the keeper's receipt. A piece from before derived
    secrets simply will not match, and is left as it is rather than filled
    with numbers that would fail at the keeper.
    """
    from . import do_secrets as SEC
    from . import do_vaultmesh as VM

    count = max(len(pieces), 1)
    restored = 0
    for position, piece in enumerate(pieces):
        receipt = piece.get("privateReceipt") or {}
        root = str(piece.get("pieceRoot", "") or receipt.get("pieceRoot", "")).strip()
        wanted = str(
            piece.get("commitmentHash", "") or receipt.get("commitmentHash", "")
        ).strip().lower()
        if not root or not wanted:
            continue

        found = None
        # A little past the number recovered: an upload can carry an entry
        # that is not a piece, so the numbers do not always end at n.
        for piece_index in range(1, count + 5):
            for attempt in range(1, MAX_SECRET_ATTEMPTS + 1):
                nonce, secret = SEC.pair(
                    file_id=str(file_id), upload_instance_id=str(upload_id),
                    piece_index=piece_index, attempt=attempt,
                )
                try:
                    if VM.compute_commitment_hash(root, nonce).lower() == wanted:
                        found = (piece_index, nonce, secret)
                        break
                except Exception:
                    break
            if found:
                break
        if not found:
            continue

        piece_index, nonce, secret = found
        piece["pieceIndex"] = piece_index
        piece["commitmentNonce"] = nonce
        piece["deletionAuthSecret"] = secret
        piece.setdefault("commitmentHash", wanted)
        restored += 1

    # A piece whose number was never learned keeps its place in the list, so
    # the pieces still number 1..n with no two the same.
    used = {int(p["pieceIndex"]) for p in pieces if p.get("pieceIndex")}
    spare = (index for index in range(1, count + 1) if index not in used)
    for position, piece in enumerate(pieces):
        if not piece.get("pieceIndex"):
            piece["pieceIndex"] = next(spare, position + 1)
    return restored


# ── writing it back into the app's own records ───────────────────────────────

def _recovered_piece(piece: dict, index: int, upload_id: str) -> dict:
    """One recovered piece, with everything the keepers gave back kept.

    The first version wrote the root and the peer and threw the rest away --
    including the signed receipt that had just been fetched from the keeper.
    The pieces table reads the keeper address and the commitment from here, so
    dropping them showed a file with six pieces and no keepers.
    """
    receipt = piece.get("privateReceipt") or {}

    def value(*names):
        for name in names:
            found = piece.get(name) or receipt.get(name)
            if found not in (None, "", 0):
                return found
        return ""

    out = {
        "pieceIndex": int(piece.get("pieceIndex") or index + 1),
        "uploadInstanceId": upload_id,
        "pieceRoot": str(piece.get("pieceRoot", "")),
        "peerId": str(piece.get("peerId", "")),
        "vkAddress": str(value("vkAddress", "expectedVkAddress")),
        "commitmentHash": str(value("commitmentHash")),
        "commitmentNonce": str(value("commitmentNonce")),
        # Derived again from the account key, so this install can delete and
        # dispute the piece and not only look at it.
        "deletionAuthSecret": str(value("deletionAuthSecret")),
        "deletionAuthHash": str(value("deletionAuthHash")),
        "paymentCommitment": str(value("paymentCommitment")),
        "serviceEnd": int(value("serviceEnd") or 0),
        "source": "recovered",
    }
    if receipt:
        out["privateReceipt"] = receipt
    return out


def _has_piece_addresses(pieces) -> bool:
    """True when these pieces are real ones, not the chain listing's rows."""
    return any(str((p or {}).get("pieceRoot", "")).strip() for p in (pieces or []))


def _registration_namespace() -> tuple[str, str]:
    """This app's chain and FileRegistrationSC, or two empty strings.

    Empty is a valid answer -- the journal has always allowed a row with no
    namespace -- but half of one is not, so they are only ever returned
    together.
    """
    try:
        chain_id = int(C.w3.eth.chain_id)
        contract = str(C.file_registration_sc.address)
        if chain_id > 0 and contract:
            return str(chain_id), contract
    except Exception as exc:
        L.log(f"[Recovery] the chain namespace could not be read: {exc}")
    return "", ""


def repair_recovered_pieces() -> int:
    """Put right what an earlier recovery left incomplete.

    Free and local, both parts: the missing half of the chain namespace, and
    the delete and dispute secrets of a piece recovered before they were
    worked out again. Without this an install would have to pay the guardians
    a second time for an answer it already has.
    """
    from . import do_piece_journal as PJ

    chain_id, contract = _registration_namespace()
    if not chain_id or not contract:
        return 0
    try:
        repaired = PJ.adopt_partial_namespace(
            C.BASE_DIR, chain_id=chain_id,
            file_registration_contract=contract, source="owner-recovery",
        )
    except Exception as exc:
        L.log(f"[Recovery] earlier piece records could not be repaired: {exc}")
        return 0
    if repaired:
        L.log(f"[Recovery] repaired {repaired} earlier piece record(s)")
    return repaired + repair_missing_secrets()


def repair_missing_secrets() -> int:
    """Work out the delete and dispute secrets of pieces that have none.

    A piece recovered before the app knew to derive them again was stored
    with no deletion secret at all, and the keeper answered every delete with
    "invalid deletion authorization secret". The secrets come from the account
    key, so this costs nothing and asks nobody.
    """
    from . import do_piece_journal as PJ

    try:
        rows = PJ.list_pieces(C.BASE_DIR, include_deleted=False)
    except Exception as exc:
        L.log(f"[Recovery] the piece records could not be read: {exc}")
        return 0

    by_upload: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        if "owner-recovery" not in (row.get("journalSources") or []):
            continue
        if str(row.get("deletionAuthSecret", "") or "").strip():
            continue
        if not str(row.get("commitmentHash", "") or "").strip():
            continue
        key = (str(row.get("fileId", "")), str(row.get("uploadInstanceId", "")))
        by_upload.setdefault(key, []).append(row)

    fixed = 0
    for (file_id, upload_id), pieces in by_upload.items():
        if not upload_id:
            continue
        # Worked out on copies, and written back as the two secrets alone.
        # A piece's number cannot be changed once the journal holds it -- it
        # is part of what identifies the obligation -- and nothing else here
        # needs to move.
        working = [dict(piece) for piece in pieces]
        if not restore_derived_secrets(file_id, upload_id, working):
            continue
        for stored, piece in zip(pieces, working):
            secret = str(piece.get("deletionAuthSecret", "") or "").strip()
            if not secret:
                continue
            try:
                PJ.record_registration(C.BASE_DIR, {
                    "fileId": stored.get("fileId", ""),
                    "pieceIndex": stored.get("pieceIndex"),
                    "pieceRoot": stored.get("pieceRoot", ""),
                    "commitmentHash": stored.get("commitmentHash", ""),
                    "uploadInstanceId": stored.get("uploadInstanceId", ""),
                    "chainId": stored.get("chainId", ""),
                    "fileRegistrationContract": stored.get(
                        "fileRegistrationContract", ""),
                    "commitmentNonce": piece.get("commitmentNonce", ""),
                    "deletionAuthSecret": secret,
                }, source="owner-recovery")
                fixed += 1
            except Exception as exc:
                L.log(f"[Recovery] a piece's secrets could not be stored: {exc}")
    if fixed:
        L.log(f"[Recovery] worked out the secrets of {fixed} piece(s) again")
    return fixed


def record_recovered_pieces(file_id, upload_id: str, pieces: list[dict]) -> int:
    """Put the recovered pieces into the piece lifecycle journal.

    policies.json lists the files; the journal is what the Stored VK Pieces
    table, the per-piece delete and the dispute all read. A fresh install has
    an empty journal, so without this the recovery finished and the table
    stayed empty -- the pieces were back, and nothing could be done with them.

    Best effort: a piece the journal refuses is logged and the rest are still
    written. Nothing here can undo a recovery that already succeeded.
    """
    from . import do_piece_journal as PJ

    chain_id, contract = _registration_namespace()
    repair_recovered_pieces()
    written = 0
    for piece in pieces:
        item = dict(piece)
        item["fileId"] = str(file_id)
        item["uploadInstanceId"] = upload_id
        # Both or neither, and always this app's own chain and contract.
        #
        # The journal takes a missing chainId from the keeper's receipt, which
        # carries one. The contract is not in the receipt, so a recovered
        # piece was written with half a namespace -- and every later lookup,
        # which asks for this chain AND this contract, missed it. The pieces
        # were listed and the delete said "Piece not found".
        item["chainId"] = chain_id
        item["fileRegistrationContract"] = contract
        if not str(item.get("commitmentHash", "")).strip():
            # The journal needs a durable identity for a piece with no
            # registered commitment. Derived from the upload and the root, so
            # recovering the same file twice writes the same row.
            item["transferId"] = (
                f"recovered-{upload_id}-{str(item.get('pieceRoot', ''))[:18]}"
            )
        try:
            PJ.record_registration(C.BASE_DIR, item, source="owner-recovery")
            written += 1
        except Exception as exc:
            L.log(f"[Recovery] piece {item.get('pieceIndex')} not journalled: {exc}")
    return written


def record_recovered_file(file_id, batch: dict, pieces: list[dict]) -> dict:
    """Put the recovered file into policies.json, under its policy.

    Merged, never overwritten: an install that still remembers some of its
    pieces keeps what it has, and recovery only fills the gaps.
    """
    records = R.load_policies_record()
    key = None
    wanted = HX.strip_hex_prefix(str(file_id)).lower()
    for candidate, record in records.items():
        if HX.strip_hex_prefix(str(record.get("policyId", ""))).lower() == wanted:
            key = candidate
            break
    if key is None:
        key = f"onchain_{wanted[:16]}"
        records[key] = {
            "policyName": f"0x{wanted[:14]}...",
            "policyId": f"0x{wanted}",
            "guardians": [],
            "threshold": int(batch["t"]),
            "created": "on-chain",
            "updated": "recovered",
            "files": [],
            "requesters": [],
        }

    # The id the upload itself used, not a new one. The file list was built
    # from the chain under that id, and it is the row the user selected, so a
    # recovery filed under "recovered-7" would leave that row empty for ever
    # and add a second row beside it.
    upload_id = str(batch.get("uploadInstanceId", "") or "") or (
        f"recovered-{int(batch['batchId'])}"
    )
    entry = {
        "uploadInstanceId": upload_id,
        "dataTag": batch["dataId"],
        "date": time.strftime("%Y-%m-%d", time.localtime(int(batch["timestamp"]))),
        "uploaded": time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(int(batch["timestamp"]))
        ),
        "batchId": int(batch["batchId"]),
        "recovered": True,
        "pieces": [_recovered_piece(piece, index, upload_id)
                   for index, piece in enumerate(pieces)],
    }

    files = records[key].setdefault("files", [])
    for position, existing in enumerate(files):
        if str(existing.get("uploadInstanceId", "")) == upload_id or (
            int(existing.get("batchId", 0) or 0) == int(batch["batchId"])
        ):
            merged = dict(existing)
            merged.update({k: v for k, v in entry.items() if k != "pieces"})
            # A row listed from the chain holds placeholders with no address;
            # those are exactly what this recovery went to fetch.
            if not _has_piece_addresses(existing.get("pieces")):
                merged["pieces"] = entry["pieces"]
            files[position] = merged
            break
    else:
        files.append(entry)

    records[key]["updated"] = "recovered"

    # The deletion secret goes to the lifecycle journal, which is a private
    # database with tight permissions, and not into policies.json, which is a
    # plain file the rest of the app reads freely. An upload has never written
    # it there either, and a recovery must not be the one that starts.
    # Copied first: what is returned still carries the secret, because the
    # journal is written from it straight after this.
    on_disk = json.loads(json.dumps(records))
    for record in on_disk.values():
        for existing in record.get("files", []):
            for piece in existing.get("pieces", []) or []:
                piece.pop("deletionAuthSecret", None)

    from pathlib import Path

    Path(R.policies_record_path()).write_text(
        json.dumps(on_disk, indent=2), encoding="utf-8"
    )
    return entry


# ── the whole thing ──────────────────────────────────────────────────────────

def recover_file(file_id, on_step=None, batch_id: int | None = None,
                 upload_id: str = "") -> dict:
    """Recover one file's pieces. Returns what was written to the records.

    The file is named by its batch or its upload id -- whichever the window
    has -- because a policy holds many of them and the guardians charge per
    request. With neither, the newest upload is used.

    Steps are reported through on_step(text) so the window can say where it
    is: this takes as long as the guardians take.
    """
    def step(text: str) -> None:
        L.log(f"[Recovery] {text}")
        if on_step is not None:
            on_step(text)

    if not C.ACCOUNT_READY:
        raise RecoveryError("this install has no account")
    if not owns_file(file_id):
        raise RecoveryError("this account does not own that policy")

    step("checking the policy on chain")
    batch = batch_for(file_id, batch_id, upload_id)
    if not batch["cidIndices"]:
        raise RecoveryError("that upload has no pieces recorded on chain")

    step("allowing myself to read my own file")
    allow_self(file_id)
    request_reencryption(file_id)

    # A request this install already paid for, and still has the key to open.
    pending = load_pending(file_id, upload_id=batch["uploadInstanceId"])
    if pending is not None:
        request_id, keypair = pending
        step(f"reusing the request already paid for (#{request_id})")
    else:
        step("making a one-time recovery key")
        keypair = new_access_keypair()

        step("asking the guardians (this pays the access fee)")
        request_id = request_access(file_id, batch, keypair)
        save_pending(file_id, request_id, keypair,
                     upload_id=batch["uploadInstanceId"])
        L.log(f"[Recovery] request id {request_id}")

    needed = guardian_threshold(file_id)
    step(f"waiting for {needed} guardians to answer")
    partials = wait_for_partials(
        request_id, needed,
        on_progress=lambda have, need, _n: step(f"{have}/{need} guardians answered"),
    )
    batch["guardianThreshold"] = needed

    step("opening the piece records")
    pieces = decrypt_pieces(batch, partials, keypair)
    if not pieces:
        raise RecoveryError("the answer held no piece records")

    # The answer is open; the key has done its work and is not kept.
    clear_pending()
    step(f"found {len(pieces)} piece(s); asking their keepers for the receipts")
    pieces = enrich_from_keepers(file_id, batch, pieces, step)

    restored = restore_derived_secrets(file_id, batch["uploadInstanceId"], pieces)
    if restored == len(pieces):
        step(f"the delete and dispute secrets of all {restored} piece(s) are back")
    elif restored:
        step(f"{restored} of {len(pieces)} piece(s) can be deleted and disputed")
    else:
        step("no delete secrets could be worked out for this upload")

    step("writing them into this install")
    entry = record_recovered_file(file_id, batch, pieces)
    kept = record_recovered_pieces(
        file_id, str(entry.get("uploadInstanceId", "")), entry.get("pieces", []))
    step(f"{kept} piece(s) are now in this install's records")
    step("done")
    return entry


def enrich_from_keepers(file_id, batch: dict, pieces: list[dict], step) -> list[dict]:
    """Fill in what only the keepers hold: the sealed copy and the receipts.

    The guardians give back where each piece is. They cannot give back the
    receipt a keeper signed, and that receipt is what a dispute has to quote --
    so without this step a recovered file can be deleted but never challenged.

    Two sources, in order of cost. The sealed copy covers the whole upload at
    once and any one keeper will do, including a keeper that is not the one
    being disputed. Failing that, each keeper is asked for its own receipt,
    which a dishonest one will simply refuse.

    Nothing here can fail the recovery: a file whose pieces are known is worth
    having even with no receipts at all.
    """
    try:
        from . import do_sealed_copy as SEAL
    except Exception:
        return pieces

    peers = [str(piece.get("peerId", "")).strip() for piece in pieces]
    peers = [peer for peer in peers if peer]

    sealed = None
    upload_id = str(batch.get("uploadInstanceId", "") or "")
    if upload_id:
        try:
            sealed = SEAL.collect(file_id, upload_id, peers)
        except Exception as exc:
            L.log(f"[Recovery] sealed copies unavailable: {exc}")

    by_root = {}
    if sealed:
        for piece in sealed.get("pieces", []):
            root = str(piece.get("pieceRoot", "")).strip().lower()
            if root:
                by_root[root] = piece
        step(f"a keeper returned the sealed copy ({len(by_root)} piece record(s))")

    recovered_receipts = 0
    for piece in pieces:
        root = str(piece.get("pieceRoot", "")).strip().lower()
        kept = by_root.get(root)
        if kept:
            # Everything the sealed copy knows and the guardians did not.
            for field in ("vkAddress", "commitmentHash", "commitmentNonce",
                          "paymentCommitment", "serviceEnd", "pieceIndex"):
                if kept.get(field) not in (None, ""):
                    piece[field] = kept[field]
            if kept.get("privateReceipt"):
                piece["privateReceipt"] = kept["privateReceipt"]
                recovered_receipts += 1
                continue

        peer = SEAL.peer_address(piece)
        if not peer or piece.get("privateReceipt"):
            continue
        try:
            receipt = SEAL.fetch_receipt_from_keeper(peer, file_id, root)
        except Exception as exc:
            L.log(f"[Recovery] {peer[:24]}... would not return a receipt: {exc}")
            receipt = None
        if receipt:
            piece["privateReceipt"] = receipt
            if receipt.get("vkAddress"):
                piece["vkAddress"] = receipt["vkAddress"]
            recovered_receipts += 1

    if recovered_receipts:
        step(f"recovered {recovered_receipts} signed receipt(s)")
    else:
        step("no receipts came back; this file can be deleted but not disputed")
    return pieces

# ── the free route: this computer's own upload records ───────────────────────
#
# Every piece of every upload leaves a durable job file behind, holding the
# keeper it went to, the piece root, the commitment, and the keeper's signed
# receipt. When the policy record is missing -- an app closed mid-upload, or
# the filing bug that matched policies by name only -- all of it is still on
# disk, and rebuilding from it costs nothing and asks nobody.
#
# Tried before the guardians, always. Paying for an answer already sitting in
# a file on the same machine would be the wrong default.

def _completed_upload_jobs(base_dir=None) -> dict:
    """Finished piece jobs, grouped by (fileId, uploadInstanceId)."""
    from pathlib import Path as _Path

    root = _Path(base_dir or C.BASE_DIR) / "transfer_jobs" / "uploads"
    grouped: dict[tuple[str, str], list[dict]] = {}
    if not root.is_dir():
        return grouped
    for path in sorted(root.glob("*.json")):
        if path.name.startswith("logical-"):
            continue          # the lifecycle record, not the result
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        result = job.get("result") or {}
        if str(job.get("status", "")).lower() != "completed" or not result:
            continue
        file_id = str(result.get("fileId") or job.get("fileId") or "").strip().lower()
        upload_id = str(
            result.get("uploadInstanceId") or job.get("uploadInstanceId") or ""
        ).strip().lower()
        if not file_id or not upload_id:
            continue
        grouped.setdefault((file_id, upload_id), []).append(result)
    return grouped


def _batch_for_upload(file_id: str, upload_id: str) -> dict | None:
    """Find which on-chain batch an upload id belongs to.

    The id is derived from the policy, the data tag and the timestamp, so each
    batch of this file is tried until one derives to the same id. That is what
    gives the rebuilt entry its real tag and date instead of a guess.
    """
    file_id_b = _file_id_bytes(file_id)
    try:
        count = int(C.dv.functions.batchCountByFileId(file_id_b).call())
    except Exception:
        count = 0
    for index in range(max(0, count - 1), -1, -1):
        try:
            found, batch_id = C.dv.functions.getBatchIdForFileAt(
                file_id_b, index
            ).call()
            if not found or int(batch_id) == 0:
                continue
            (
                _fid, _owner, data_id, ts, n_ida, t_ida, key_epoch, cid_indices,
            ) = C.dv.functions.getBatch(int(batch_id)).call()
        except Exception:
            continue
        try:
            derived = HX.derive_upload_instance_id(file_id, str(data_id), int(ts))
        except Exception:
            continue
        if str(derived).strip().lower() == str(upload_id).strip().lower():
            return {
                "batchId": int(batch_id),
                "dataId": str(data_id),
                "timestamp": int(ts),
                "n": int(n_ida),
                "t": int(t_ida),
                "keyEpoch": int(key_epoch),
                "cidIndices": [int(x) for x in cid_indices],
            }
    return None


def rebuild_from_local_jobs(base_dir=None) -> int:
    """Put back any upload this computer finished but did not file.

    Returns how many files were added. Safe to run at any time: an upload the
    records already hold is left alone, and a job whose batch cannot be found
    on chain is skipped rather than filed under a made-up tag.
    """
    from . import do_records as RECORDS

    grouped = _completed_upload_jobs(base_dir)
    if not grouped:
        return 0

    known = set()
    for record in RECORDS.load_policies_record().values():
        for existing in record.get("files", []):
            upload_id = str(existing.get("uploadInstanceId", "")).strip().lower()
            if upload_id:
                known.add(upload_id)

    added = 0
    for (file_id, upload_id), results in grouped.items():
        if upload_id in known:
            continue
        batch = _batch_for_upload(file_id, upload_id)
        if batch is None:
            L.log(f"[Recovery] upload {upload_id[:12]}... has no batch on chain; skipped")
            continue
        pieces = sorted(results, key=lambda item: int(item.get("pieceIndex", 0) or 0))
        payload = [
            {
                "pieceIndex": piece.get("pieceIndex", 0),
                "uploadInstanceId": upload_id,
                "pieceRoot": piece.get("pieceRoot", ""),
                "peerId": piece.get("peerId", ""),
                "vkAddress": piece.get("expectedVkAddress", ""),
                "privateReceipt": piece.get("privateReceipt") or {},
            }
            for piece in pieces
        ]
        date_str = time.strftime("%Y-%m-%d", time.localtime(int(batch["timestamp"])))
        RECORDS.save_file_upload_record(
            "", batch["dataId"], date_str, int(batch["timestamp"]), payload,
            file_id=file_id,
        )
        L.log(
            f"[Recovery] rebuilt {batch['dataId']} ({len(payload)} piece(s)) "
            f"from this computer's own upload records"
        )
        added += 1
    return added
