# do_secrets.py — the per-piece secrets, worked out from the account key.
#
# Two secrets are made for every piece an upload produces:
#
#   commitmentNonce     hashed with the piece root into the commitment the
#                       chain stores, and needed again to file a dispute
#   deletionAuthSecret  handed to the keeper when the owner wants the piece
#                       deleted; the chain stored only its hash at upload
#
# Both used to be random numbers kept in one file on one computer. Lose that
# computer and the pieces are still out there, still paid for, and their owner
# can neither delete them nor dispute a keeper that misbehaves -- the proof is
# simply gone, with nothing on the chain able to bring it back.
#
# So they are derived instead: HMAC of a root key, which is itself an HMAC of
# the account's private key. Same account, same piece, same numbers, on any
# machine, for ever. Nothing has to be stored for recovery, and nothing about
# the shape of an upload changes -- the keeper still receives a nonce, the
# chain still stores a hash, and neither can tell a derived number from a
# random one.
#
# Why this is not weaker than random:
#
#   * HMAC-SHA256 output is indistinguishable from random without the key, so
#     nobody can guess one secret from another, or from the hashes on chain;
#   * every secret has its own label, so the nonce and the deletion secret for
#     the same piece are unrelated, and two pieces never share;
#   * the attempt number is part of the input, so a retried piece gets fresh
#     secrets exactly as it did when they were random;
#   * revealing a deletion secret on chain -- which is what deleting does --
#     tells nobody anything about the account key or any other piece;
#   * an attacker who has the account key can already sign as the owner, so
#     deriving from it costs nothing that was not already lost.

from __future__ import annotations

import hashlib
import hmac
import secrets as _random

# Changing any of these changes every secret this module makes, which would
# strand every piece already stored. They are constants, not settings.
ROOT_LABEL = b"FileTrust/DO/piece-secrets/v1"
NONCE_LABEL = b"commitment-nonce"
DELETION_LABEL = b"deletion-auth-secret"


def _account_key() -> bytes:
    """The signing key of this install, or b"" when there is not one yet.

    Imported late on purpose: this module is used by the transfer manager,
    which is deliberately importable without the whole web3 configuration
    behind it.
    """
    try:
        from . import do_config as C

        account = getattr(C, "DO_ACCOUNT", None)
        if account is None:
            return b""
        return bytes(account.key)
    except Exception:
        return b""


def _root(key: bytes) -> bytes:
    return hmac.new(key, ROOT_LABEL, hashlib.sha256).digest()


def _field(value) -> bytes:
    """One input, length-prefixed, so two different sets of fields can never
    produce the same message to sign.

    A leading 0x is removed first. The same file id reaches this module
    written both ways -- the durable job records keep it bare, the chain code
    keeps the prefix -- and a recovery that re-derives from the other spelling
    would otherwise get different secrets and silently fail to match anything.
    """
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    raw = text.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def derive(label: bytes, *, file_id: str, upload_instance_id: str,
           piece_index, attempt, key: bytes | None = None) -> str:
    """One secret, as 0x-prefixed 32-byte hex, or "" with no account key."""
    signing_key = _account_key() if key is None else key
    if not signing_key:
        return ""
    message = b"".join((
        label,
        _field(file_id),
        _field(upload_instance_id),
        _field(int(piece_index) if str(piece_index).strip() != "" else ""),
        _field(int(attempt or 1)),
    ))
    return "0x" + hmac.new(_root(signing_key), message, hashlib.sha256).hexdigest()


def _random_hex() -> str:
    return "0x" + _random.token_hex(32)


def commitment_nonce(*, file_id: str, upload_instance_id: str, piece_index,
                     attempt=1, key: bytes | None = None) -> str:
    """The nonce for this piece; random only when there is no account to
    derive from, so an install without a key still works as it always did."""
    return derive(
        NONCE_LABEL, file_id=file_id, upload_instance_id=upload_instance_id,
        piece_index=piece_index, attempt=attempt, key=key,
    ) or _random_hex()


def deletion_auth_secret(*, file_id: str, upload_instance_id: str, piece_index,
                         attempt=1, key: bytes | None = None) -> str:
    return derive(
        DELETION_LABEL, file_id=file_id, upload_instance_id=upload_instance_id,
        piece_index=piece_index, attempt=attempt, key=key,
    ) or _random_hex()


def pair(*, file_id: str, upload_instance_id: str, piece_index, attempt=1,
         key: bytes | None = None) -> tuple[str, str]:
    """Both secrets for a piece, in the order the job record stores them."""
    return (
        commitment_nonce(file_id=file_id, upload_instance_id=upload_instance_id,
                         piece_index=piece_index, attempt=attempt, key=key),
        deletion_auth_secret(file_id=file_id, upload_instance_id=upload_instance_id,
                             piece_index=piece_index, attempt=attempt, key=key),
    )
