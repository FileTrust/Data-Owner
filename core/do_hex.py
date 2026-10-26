"""Strict hexadecimal parsing for DO trust-boundary values."""

from __future__ import annotations

import hashlib


def strip_hex_prefix(value: object) -> str:
    """Return hex text after removing exactly one optional 0x prefix."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    text = str(value or "").strip()
    return text[2:] if text[:2].lower() == "0x" else text


def normalize_hex(
    value: object,
    *,
    expected_bytes: int | None = None,
    field: str = "hex value",
    allow_empty: bool = False,
) -> str:
    """Validate hex text and return lowercase, unprefixed representation."""
    clean = strip_hex_prefix(value)
    if not clean:
        if allow_empty:
            return ""
        raise ValueError(f"{field} is empty")
    if len(clean) % 2:
        raise ValueError(f"{field} must contain an even number of hex digits")
    if expected_bytes is not None and len(clean) != expected_bytes * 2:
        raise ValueError(
            f"{field} must be exactly {expected_bytes} bytes, got {len(clean) // 2}"
        )
    try:
        bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError(f"{field} contains non-hexadecimal characters") from exc
    return clean.lower()


def hex_to_bytes(
    value: object,
    *,
    expected_bytes: int | None = None,
    field: str = "hex value",
) -> bytes:
    return bytes.fromhex(
        normalize_hex(value, expected_bytes=expected_bytes, field=field)
    )


def hex_to_bytes_or_zero(value: object, *, size: int, field: str) -> bytes:
    if not strip_hex_prefix(value):
        return b"\x00" * size
    return hex_to_bytes(value, expected_bytes=size, field=field)


def prefixed_hex(
    value: object,
    *,
    expected_bytes: int | None = None,
    field: str = "hex value",
) -> str:
    return "0x" + normalize_hex(value, expected_bytes=expected_bytes, field=field)


def normalize_file_id(value: object) -> str:
    """Return the one durable representation used for a FileTrust file ID.

    File IDs are bytes32 values.  Keeping the stored/key form unprefixed
    preserves compatibility with the existing DO records while making
    ``0x...``, ``0X...`` and unprefixed input resolve to the same identity.
    """
    return normalize_hex(value, expected_bytes=32, field="fileId")


def prefixed_file_id(value: object) -> str:
    """Return a canonical bytes32 file ID for Web3/JSON boundaries."""
    return "0x" + normalize_file_id(value)


def derive_upload_instance_id(
    file_id: object,
    data_tag: object,
    timestamp: object,
) -> str:
    """Return a private stable ID for one DataVault upload generation.

    ``fileId`` identifies a policy and is intentionally reusable.  The
    DataVault batch identity is the policy plus its private data tag and UTC
    timestamp.  Length-prefixing avoids ambiguous string concatenation and the
    domain prefix prevents this digest being confused with any on-chain
    FileTrust commitment.
    """
    policy_id = bytes.fromhex(normalize_file_id(file_id))
    tag = str(data_tag or "").encode("utf-8")
    if not tag:
        raise ValueError("dataTag is empty")
    try:
        ts = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise ValueError("upload timestamp is invalid") from exc
    if ts < 0 or ts >= 1 << 64:
        raise ValueError("upload timestamp is outside uint64 range")
    material = (
        b"FileTrust/upload-instance/v1\x00"
        + policy_id
        + len(tag).to_bytes(4, "big")
        + tag
        + ts.to_bytes(8, "big")
    )
    return hashlib.sha256(material).hexdigest()


def is_fixed_hex(value: object, *, size: int) -> bool:
    try:
        normalize_hex(value, expected_bytes=size)
        return True
    except ValueError:
        return False
