"""Baby Jubjub + V2 ElGamal crypto primitives for the Data Owner.

Self-contained — no imports from outside App/DO/.
"""
import hashlib
import secrets
from typing import Optional, Tuple

try:
    from web3 import Web3
except Exception:
    Web3 = None

BABY_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BABY_Q = 21888242871839275222246405745257275088614511777268538073601725287587578984328
BABY_L = BABY_Q // 8
BABY_A = 168700
BABY_D = 168696
BABY_G = (
    16540640123574156134436876038791482806971768689494387082833631921987005038935,
    20819045374670962167435360035096875258406992893633759881276124905556507972311,
)

BabyPoint = Optional[Tuple[int, int]]


def _keccak(data: bytes) -> bytes:
    if Web3 is not None:
        return bytes(Web3.keccak(data))
    try:
        from Crypto.Hash import keccak
        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
    except Exception as exc:
        raise RuntimeError("Keccak-256 required for Solidity-compatible context hashing") from exc


def _mod(x: int) -> int:
    return x % BABY_P


def _inv(x: int) -> int:
    return pow(x % BABY_P, BABY_P - 2, BABY_P)


def baby_is_on_curve(point: BabyPoint) -> bool:
    if point is None:
        return True
    x, y = point
    return (BABY_A * x * x + y * y - 1 - BABY_D * x * x * y * y) % BABY_P == 0


def baby_add(p: BabyPoint, q: BabyPoint) -> BabyPoint:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    x1x2 = _mod(x1 * x2)
    y1y2 = _mod(y1 * y2)
    dxxyy = _mod(BABY_D * x1x2 * y1y2)
    x3 = _mod((_mod(x1 * y2) + _mod(y1 * x2)) * _inv(1 + dxxyy))
    y3 = _mod((y1y2 - _mod(BABY_A * x1x2)) * _inv(1 - dxxyy))
    return x3, y3


def baby_neg(p: BabyPoint) -> BabyPoint:
    if p is None:
        return None
    return ((-p[0]) % BABY_P, p[1])


def baby_mul(scalar: int, point: BabyPoint = BABY_G) -> BabyPoint:
    if point is None:
        return None
    k = int(scalar) % BABY_L
    if k == 0:
        return None
    result: BabyPoint = None
    addend: BabyPoint = point
    while k:
        if k & 1:
            result = baby_add(result, addend)
        k >>= 1
        if k:
            addend = baby_add(addend, addend)
    return result


def xor_stream(data: bytes, key_material: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        out.extend(hashlib.sha256(key_material + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out[: len(data)]))


def _point_bytes(point: BabyPoint) -> bytes:
    if point is None:
        raise ValueError("point at infinity")
    return int(point[0]).to_bytes(32, "big") + int(point[1]).to_bytes(32, "big")


def v2_mask_key(shared: BabyPoint, context: bytes = b"") -> bytes:
    return hashlib.sha256(b"FileTrust-ZKDKG-V2-ElGamal" + _point_bytes(shared) + context).digest()


def v2_encrypt_to_pk(public_key: BabyPoint, plaintext: bytes, context: bytes = b""):
    if not baby_is_on_curve(public_key):
        raise ValueError("V2 public key is not on Baby Jubjub")
    r = secrets.randbelow(BABY_L - 1) + 1
    c1 = baby_mul(r, BABY_G)
    shared = baby_mul(r, public_key)
    if c1 is None or shared is None:
        raise RuntimeError("V2 encryption produced point at infinity")
    c2 = xor_stream(plaintext, v2_mask_key(shared, context))
    return c1, c2


def v2_batch_encryption_secret(public_key: BabyPoint):
    if not baby_is_on_curve(public_key):
        raise ValueError("V2 public key is not on Baby Jubjub")
    r = secrets.randbelow(BABY_L - 1) + 1
    c1 = baby_mul(r, BABY_G)
    shared = baby_mul(r, public_key)
    if c1 is None or shared is None:
        raise RuntimeError("V2 batch encryption produced point at infinity")
    return c1, shared


def v2_encrypt_with_shared(shared: BabyPoint, plaintext: bytes, context: bytes = b"") -> bytes:
    if shared is None:
        raise ValueError("missing V2 shared point")
    return xor_stream(plaintext, v2_mask_key(shared, context))


def v2_decrypt_with_shared(shared: BabyPoint, c2: bytes, context: bytes = b"") -> bytes:
    if shared is None:
        raise ValueError("missing V2 shared point")
    return xor_stream(bytes(c2), v2_mask_key(shared, context))


def v2_elgamal_decrypt(e1: BabyPoint, e2: BabyPoint, sk_req: int) -> BabyPoint:
    """Recover D from El-Gamal ciphertext: D = E2 - sk_req * E1."""
    s = baby_mul(sk_req, e1)
    if s is None:
        raise ValueError("sk_req * E1 is point at infinity")
    return baby_add(e2, baby_neg(s))


def v2_lagrange_coeff(x_j: int, x_set: list) -> int:
    xj = int(x_j) % BABY_L
    num = 1
    den = 1
    for xm in x_set:
        xm = int(xm) % BABY_L
        if xm == xj:
            continue
        num = (num * (-xm)) % BABY_L
        den = (den * (xj - xm)) % BABY_L
    return (num * pow(den, BABY_L - 2, BABY_L)) % BABY_L


def v2_combine_partials(partials: list) -> BabyPoint:
    indices = [int(i) for i, _ in partials]
    acc: BabyPoint = None
    for idx, point in partials:
        lam = v2_lagrange_coeff(int(idx), indices)
        acc = baby_add(acc, baby_mul(lam, point))
    return acc
