# do_sealed_copy.py — a copy of this upload's records, left with the keepers.
#
# After a reinstall the guardians can give back the piece addresses and the
# keepers holding them (do_recovery), and the per-piece secrets are derived
# from the account key (do_secrets). One thing is left: the receipt each keeper
# signed at upload. It is the owner's only evidence in a storage dispute, and
# the only other copy is on the disk of the keeper it might be used against. A
# keeper that stays quiet after an owner reinstalls can never be challenged.
#
# So every keeper of an upload is given a sealed copy of the whole upload's
# records -- all the receipts, not only its own. The pieces of one file live on
# different keepers, so keeper A holds the evidence about keeper C, and C
# cannot reach it. Any one of them answering is enough.
#
# The copy is encrypted to the owner's own key. A keeper stores bytes it cannot
# read, and the only party who can open it is the one who made it.
#
# Why not the chain: it would be a few hundred bytes of gas per piece, for
# every upload, for ever, to hold something only one person ever reads. The
# keepers are already paid to store this file.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from . import do_config as C
from . import do_log as L

FORMAT = "filetrust-sealed-copy/1"

# Well inside the keeper's limit, and far above what an upload's records need.
MAX_SEALED_BYTES = 200 * 1024

_KEY_LABEL = b"FileTrust/DO/sealed-copy/v1"


def _vault_key() -> bytes:
    """A key for sealing, derived from the account key and used nowhere else.

    The account key itself never encrypts anything: it signs. One label, one
    purpose, so a weakness in either cannot be carried into the other.
    """
    account = getattr(C, "DO_ACCOUNT", None)
    if account is None:
        raise RuntimeError("this install has no account key")
    return hmac.new(bytes(account.key), _KEY_LABEL, hashlib.sha256).digest()


def seal(record: dict) -> str:
    """Encrypt an upload's records for this account. Returns base64."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    blob = AESGCM(_vault_key()).encrypt(nonce, body, FORMAT.encode("utf-8"))
    if len(blob) + len(nonce) > MAX_SEALED_BYTES:
        raise RuntimeError("this upload's records are too large to leave with keepers")
    return base64.b64encode(nonce + blob).decode("ascii")


def unseal(sealed: str) -> dict:
    """Open a sealed copy. Raises when it is not ours or has been tampered."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(str(sealed).strip(), validate=True)
    if len(raw) <= 12:
        raise RuntimeError("the sealed copy is too short to be one")
    try:
        body = AESGCM(_vault_key()).decrypt(raw[:12], raw[12:], FORMAT.encode("utf-8"))
    except InvalidTag as exc:
        raise RuntimeError(
            "that sealed copy was not made by this account, or has been altered"
        ) from exc
    record = json.loads(body.decode("utf-8"))
    if not isinstance(record, dict) or record.get("format") != FORMAT:
        raise RuntimeError("the sealed copy is not in a shape this app knows")
    return record


def build_record(file_id: str, upload_instance_id: str, pieces: list[dict]) -> dict:
    """What is worth keeping about one upload.

    Only what cannot be had another way: the keeper's signed receipt, and the
    facts a dispute has to quote. The piece addresses are in here too, so a
    sealed copy alone can rebuild the file list without paying the guardians --
    but it is not the main route, because finding the keepers needs them.
    """
    kept = []
    for piece in pieces:
        receipt = piece.get("privateReceipt") or {}
        kept.append({
            "pieceIndex": piece.get("pieceIndex"),
            "pieceRoot": piece.get("pieceRoot", ""),
            "peerId": piece.get("peerId", ""),
            "vkAddress": piece.get("vkAddress", ""),
            "commitmentHash": piece.get("commitmentHash", ""),
            "commitmentNonce": piece.get("commitmentNonce", ""),
            "paymentCommitment": piece.get("paymentCommitment", ""),
            "serviceEnd": piece.get("serviceEnd"),
            "privateReceipt": receipt,
        })
    return {
        "format": FORMAT,
        "fileId": str(file_id),
        "uploadInstanceId": str(upload_instance_id),
        "owner": str(getattr(C, "DO", "")),
        "sealedAt": int(time.time()),
        "pieces": kept,
    }


# ── talking to the keepers ───────────────────────────────────────────────────

def _auth(message: str) -> tuple[str, int, str]:
    """Sign a recovery request the way the keeper expects to verify it."""
    from eth_account.messages import encode_defunct

    requester = C.w3.to_checksum_address(C.DO_ACCOUNT.address)
    issued_at = int(time.time())
    signed = C.DO_ACCOUNT.sign_message(encode_defunct(text=message.format(
        requester=requester, issued_at=issued_at,
    )))
    return requester, issued_at, signed.signature.hex()


def _vault_message(action: str, file_id: str, upload_id: str) -> str:
    return (
        "FileTrust VaultMesh RECOVERY-VAULT\n"
        f"action={action}\n"
        f"fileId={_normalise_file_id(file_id)}\n"
        f"uploadId={str(upload_id).strip().lower()}\n"
        "requester={requester}\n"
        "issuedAt={issued_at}"
    )


def _receipt_message(file_id: str, piece_root: str) -> str:
    return (
        "FileTrust VaultMesh RECOVERY-RECEIPT\n"
        f"fileId={_normalise_file_id(file_id)}\n"
        f"pieceRoot={_normalise_root(piece_root)}\n"
        "requester={requester}\n"
        "issuedAt={issued_at}"
    )


def _normalise_file_id(file_id: str) -> str:
    """Exactly the keeper's normalizeFileID, including for an empty value.

    The signature covers this text, so a difference of one character between
    the two sides means every request is refused and nobody can see why.
    """
    text = str(file_id or "").strip()
    if text[:2].lower() == "0x":
        text = text[2:]
    return "0x" + text.lower()


def _normalise_root(piece_root: str) -> str:
    """Exactly the keeper's normalizeRoot."""
    text = str(piece_root or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return "0x" + text


def _run(args: list[str]) -> dict:
    from . import do_vaultmesh as VM

    try:
        out = VM.run_vaultmesh_cmd([C.VAULTMESH_CMD, *args])
        return json.loads(out) if out else {}
    except Exception as exc:
        return {"error": str(exc)}


def leave_with_keeper(peer: str, file_id: str, upload_id: str, sealed: str) -> bool:
    """Give one keeper the sealed copy. False when it would not take it."""
    requester, issued_at, signature = _auth(_vault_message("store", file_id, upload_id))
    response = _run([
        "--mode", "recovery-vault",
        "--peer", peer,
        "--file-id", _normalise_file_id(file_id),
        "--recovery-upload-id", str(upload_id),
        "--recovery-sealed", sealed,
        "--requester", requester,
        "--issued-at", str(issued_at),
        "--sig", signature,
    ])
    if response.get("error"):
        L.log(f"[Sealed copy] {peer[:24]}... did not store it: {response['error']}")
        return False
    return bool(response.get("stored"))


def fetch_from_keeper(peer: str, file_id: str, upload_id: str) -> dict | None:
    """Ask one keeper for the sealed copy. None when it has none, or refuses."""
    requester, issued_at, signature = _auth(_vault_message("fetch", file_id, upload_id))
    response = _run([
        "--mode", "recovery-vault",
        "--peer", peer,
        "--file-id", _normalise_file_id(file_id),
        "--recovery-upload-id", str(upload_id),
        "--requester", requester,
        "--issued-at", str(issued_at),
        "--sig", signature,
    ])
    if response.get("error") or not response.get("found"):
        return None
    try:
        return unseal(str(response.get("sealed", "")))
    except Exception as exc:
        L.log(f"[Sealed copy] {peer[:24]}... returned one we cannot open: {exc}")
        return None


def fetch_receipt_from_keeper(peer: str, file_id: str, piece_root: str) -> dict | None:
    """Ask the keeper that signed a receipt to hand it back."""
    requester, issued_at, signature = _auth(_receipt_message(file_id, piece_root))
    response = _run([
        "--mode", "recovery-receipt",
        "--peer", peer,
        "--file-id", _normalise_file_id(file_id),
        "--piece-root", _normalise_root(piece_root),
        "--requester", requester,
        "--issued-at", str(issued_at),
        "--sig", signature,
    ])
    if response.get("error") or not response.get("found"):
        return None
    receipt = response.get("receipt")
    return receipt if isinstance(receipt, dict) else None


def peer_address(piece: dict) -> str:
    """The address vaultmesh can actually dial for this piece's keeper.

    A bare peer id is not one. The upload records the full multiaddr it used,
    so that is taken first; for a piece recovered from the guardians only the
    peer id comes back, and discovery is asked to turn it into an address.
    Getting this wrong is silent -- every keeper simply refuses -- which is
    exactly how the first version shipped.
    """
    for field in ("resolvedMultiaddr", "multiaddr", "vkPeer", "peer"):
        value = str(piece.get(field, "") or "").strip()
        if value.startswith("/"):
            return value
    return resolve_peer_id(str(piece.get("peerId", "") or "").strip())


def resolve_peer_id(peer_id: str) -> str:
    """Ask discovery for a keeper's address. "" when it is not known there."""
    peer_id = str(peer_id or "").strip()
    if not peer_id:
        return ""
    if peer_id.startswith("/"):
        return peer_id
    try:
        from . import do_directory as D

        D.refresh()
        for keeper in D.keepers():
            multiaddr = str(keeper.get("multiaddr", "") or "").strip()
            if multiaddr and peer_id in multiaddr:
                return multiaddr
    except Exception as exc:
        L.log(f"[Sealed copy] could not resolve {peer_id[:16]}...: {exc}")
    return ""


def distribute(file_id: str, upload_instance_id: str, pieces: list[dict]) -> int:
    """Leave one sealed copy with every keeper of this upload.

    Best effort, and quiet about it: an upload that has already succeeded must
    not be reported as failed because a keeper would not take a backup. The
    count of keepers that accepted is logged, because one is enough and none
    is worth knowing about.
    """
    peers = []
    for piece in pieces:
        address = peer_address(piece)
        if address and address not in peers:
            peers.append(address)
    if not peers:
        L.log("[Sealed copy] no keeper address to send it to")
        return 0

    try:
        sealed = seal(build_record(file_id, upload_instance_id, pieces))
    except Exception as exc:
        L.log(f"[Sealed copy] could not be made: {exc}")
        return 0

    kept = 0
    for peer in peers:
        try:
            if leave_with_keeper(peer, file_id, upload_instance_id, sealed):
                kept += 1
        except Exception as exc:
            L.log(f"[Sealed copy] {peer[:24]}... failed: {exc}")
    L.log(
        f"[Sealed copy] left with {kept} of {len(peers)} keeper(s) for upload "
        f"{upload_instance_id}"
    )
    return kept


def collect(file_id: str, upload_instance_id: str, peers: list[str]) -> dict | None:
    """Ask each keeper in turn until one returns the sealed copy.

    One honest keeper is enough, which is the point of leaving a copy with all
    of them: the keeper being disputed is not the only one holding the proof.
    """
    for peer in peers:
        address = peer if str(peer).startswith("/") else resolve_peer_id(str(peer))
        if not address:
            continue
        record = fetch_from_keeper(address, file_id, upload_instance_id)
        if record is not None:
            L.log(f"[Sealed copy] recovered from {str(peer)[:24]}...")
            return record
    L.log("[Sealed copy] no keeper returned one")
    return None
