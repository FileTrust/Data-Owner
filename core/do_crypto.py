# do_crypto.py — EC math, AES-CTR+HMAC encryption, Rabin IDA dispersal/reconstruction.

import os
import json
import base64
import hashlib
import secrets
import struct
from typing import Optional, Tuple

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.exceptions import InvalidSignature

from . import do_config as C

# Re-export Baby Jubjub / V2 helpers (from do_v2_crypto via do_config) for other modules.
from .do_config import (  # noqa: F401
    baby_add, baby_is_on_curve, baby_mul,
    v2_batch_encryption_secret, v2_encrypt_to_pk,
    v2_encrypt_with_shared, v2_lagrange_coeff,
)

Point = Optional[Tuple[int, int]]


# ── secp256k1 EC math ─────────────────────────────────────────────────────────

def mod_inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def is_on_curve(P: Point) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + C.a * x + C.b)) % C.p == 0


def point_add(P: Point, Q: Point) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        if y1 == 0:
            return None
        s = (3 * x1 * x1 + C.a) * mod_inv(2 * y1 % C.p, C.p) % C.p
    else:
        if x1 == x2:
            return None
        s = (y2 - y1) * mod_inv((x2 - x1) % C.p, C.p) % C.p
    x3 = (s * s - x1 - x2) % C.p
    y3 = (s * (x1 - x3) - y1) % C.p
    return (x3, y3)


def scalar_mult(k: int, P: Point) -> Point:
    if k % C.n_order == 0 or P is None:
        return None
    k = k % C.n_order
    result = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def xor_stream_encrypt(data: bytes, key_material: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        h = hashlib.sha256(key_material + counter.to_bytes(4, "big")).digest()
        out.extend(h)
        counter += 1
    ks = bytes(out[:len(data)])
    return bytes(d ^ k for d, k in zip(data, ks))


def telg_encrypt_str_ec(PK: Point, text: str):
    if not is_on_curve(PK):
        raise ValueError("PK not on curve")
    r = int.from_bytes(
        hashlib.sha256(text.encode("utf-8") + secrets.token_bytes(16)).digest(), "big"
    ) % C.n_order
    if r == 0:
        r = 1
    C1 = scalar_mult(r, C.G)
    Sp = scalar_mult(r, PK)
    if C1 is None or Sp is None:
        raise RuntimeError("INF in encryption")
    Sx, _ = Sp
    key_material = Sx.to_bytes((Sx.bit_length() + 7) // 8, "big")
    C2 = xor_stream_encrypt(text.encode("utf-8"), key_material)
    return C1, C2


def get_finalized_v2_public_key(file_id: bytes):
    if C.coordinator_v2 is None:
        raise RuntimeError("ZKDKG_V2 coordinator contract is not configured")
    (exists, finalized, _data_owner, _t, _n, key_epoch, share_version, pkx, pky) = (
        C.coordinator_v2.functions.getV2Key(file_id).call()
    )
    if not exists or not finalized:
        raise RuntimeError("ZKDKG_V2 key is not finalized")
    pk = (int(pkx), int(pky))
    if not baby_is_on_curve(pk):
        raise RuntimeError("ZKDKG_V2 public key is not on Baby Jubjub")
    return pk, int(key_epoch), int(share_version)


def telg_v2_encrypt_str(PK: Tuple[int, int], text: str):
    return v2_encrypt_to_pk(PK, text.encode("utf-8"))


# ── AES-CTR + HMAC-SHA256 ─────────────────────────────────────────────────────

def generate_keys():
    master = secrets.token_bytes(64)
    return master[:32], master[32:]


def encrypt_file(in_path: str, out_path: str, key_json_path: str) -> None:
    enc_key, mac_key = generate_keys()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(iv)
        while True:
            chunk = fin.read(C.CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            fout.write(ct)
            h.update(ct)
        ct_final = encryptor.finalize()
        if ct_final:
            fout.write(ct_final)
            h.update(ct_final)
        tag = h.finalize()
        fout.write(tag)
    key_info = {
        "enc_key": base64.b64encode(enc_key).decode("utf-8"),
        "mac_key": base64.b64encode(mac_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag_size": len(tag),
        "cipher": {"algorithm": "AES", "mode": "CTR", "key_size_bits": 256},
        "mac": {"algorithm": "HMAC", "hash": "SHA256"},
    }
    with open(key_json_path, "w", encoding="utf-8") as f:
        json.dump(key_info, f, indent=2)


def decrypt_file(enc_path: str, out_path: str, key_json_path: str) -> None:
    with open(key_json_path, "r", encoding="utf-8") as f:
        key_info = json.load(f)
    enc_key = base64.b64decode(key_info["enc_key"])
    mac_key = base64.b64decode(key_info["mac_key"])
    tag_size = key_info.get("tag_size", 32)
    file_size = os.path.getsize(enc_path)
    if file_size < 16 + tag_size:
        raise ValueError("Encrypted file too small or corrupted")
    with open(enc_path, "rb") as fin, open(out_path, "wb") as fout:
        iv = fin.read(16)
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        ct_bytes_left = file_size - 16 - tag_size
        while ct_bytes_left > 0:
            to_read = min(C.CHUNK_SIZE, ct_bytes_left)
            chunk = fin.read(to_read)
            if not chunk:
                raise ValueError("Unexpected end of file during ciphertext read")
            h.update(chunk)
            pt = decryptor.update(chunk)
            fout.write(pt)
            ct_bytes_left -= len(chunk)
        tag = fin.read(tag_size)
        if len(tag) != tag_size:
            raise ValueError("Could not read authentication tag")
        try:
            h.verify(tag)
        except InvalidSignature:
            raise ValueError("Authentication failed: wrong key or file tampered")
        pt_final = decryptor.finalize()
        if pt_final:
            fout.write(pt_final)


def encrypt_with_default_paths(in_path: str):
    folder, base = os.path.split(in_path)
    name, ext = os.path.splitext(base)
    enc_path = os.path.join(folder, f"{name}_enc{ext}")
    key_json_path = os.path.join(C.BASE_DIR, f"{name}_enc_keys.json")
    encrypt_file(in_path, enc_path, key_json_path)
    return enc_path, key_json_path


# ── Rabin IDA — GF(256) ───────────────────────────────────────────────────────

POLY = 0x11B


def _gf_mul_bitwise(x: int, y: int) -> int:
    res = 0
    while y:
        if y & 1:
            res ^= x
        x <<= 1
        if x & 0x100:
            x ^= POLY
        y >>= 1
    return res & 0xFF


def _build_tables():
    mul = np.zeros((256, 256), dtype=np.uint8)
    for x in range(256):
        for y in range(256):
            mul[x, y] = _gf_mul_bitwise(x, y)
    inv = np.zeros(256, dtype=np.uint8)
    for x in range(1, 256):
        row = mul[x]
        idx = np.where(row == 1)[0]
        if idx.size == 0:
            raise RuntimeError(f"No inverse for {x} in GF(256)")
        inv[x] = idx[0]
    return mul, inv


GF_MUL_TABLE, INV_TABLE = _build_tables()


def gf_inv(x: int) -> int:
    if x == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(256)")
    return int(INV_TABLE[x])


def build_generator_matrix(n: int, m: int) -> np.ndarray:
    if n + m > 255:
        raise ValueError("For Cauchy matrix, require n + m <= 255")
    x_values = list(range(1, n + 1))
    y_values = [n + 1 + j for j in range(m)]
    c = np.empty((n, m), dtype=np.uint8)
    for i in range(n):
        xi = x_values[i]
        for j in range(m):
            diff = xi ^ y_values[j]
            if diff == 0:
                raise RuntimeError("x and y collided")
            c[i, j] = INV_TABLE[diff]
    return c


def gf_mat_inv(M: np.ndarray) -> np.ndarray:
    M = M.astype(np.uint8, copy=True)
    m = M.shape[0]
    A = np.zeros((m, 2 * m), dtype=np.uint8)
    A[:, :m] = M
    for i in range(m):
        A[i, m + i] = 1
    for col in range(m):
        pivots = np.nonzero(A[col:, col])[0]
        if pivots.size == 0:
            raise ValueError("Matrix not invertible")
        pivot = col + pivots[0]
        if pivot != col:
            tmp = A[col].copy()
            A[col] = A[pivot]
            A[pivot] = tmp
        pivot_val = int(A[col, col])
        inv_pivot = gf_inv(pivot_val)
        row = A[col]
        for c_idx in range(2 * m):
            row[c_idx] = GF_MUL_TABLE[inv_pivot, row[c_idx]]
        for r in range(m):
            if r == col:
                continue
            factor = int(A[r, col])
            if factor:
                src = A[col]
                dst = A[r]
                for c_idx in range(2 * m):
                    dst[c_idx] ^= GF_MUL_TABLE[factor, src[c_idx]]
    return A[:, m:]


def ida_disperse_file(input_path: str, out_dir: str, n: int, m: int):
    if n <= 0 or m <= 0 or m > n or n > 255 or m > 255:
        raise ValueError("Require 0 < m <= n <= 255")
    os.makedirs(out_dir, exist_ok=True)
    with open(input_path, "rb") as f:
        data_bytes = f.read()
    file_size = len(data_bytes)
    pad_len = (-file_size) % m
    if pad_len:
        data_bytes += b"\x00" * pad_len
    data = np.frombuffer(data_bytes, dtype=np.uint8)
    num_blocks = data.size // m
    blocks = data.reshape(num_blocks, m)
    Gm = build_generator_matrix(n, m)
    shares = []
    for i in range(n):
        row = Gm[i]
        acc = np.zeros(num_blocks, dtype=np.uint8)
        for j in range(m):
            coef = int(row[j])
            col_data = blocks[:, j]
            acc ^= GF_MUL_TABLE[coef, col_data]
        shares.append(acc)
    base_name = os.path.basename(input_path)
    for i in range(n):
        share_name = f"{base_name}_p{i + 1}_of_{n}"
        share_path = os.path.join(out_dir, share_name)
        with open(share_path, "wb") as sf:
            header = (
                b"RIDA"
                + bytes([1, n & 0xFF, m & 0xFF, i & 0xFF])
                + struct.pack(">Q", file_size)
            )
            sf.write(header)
            sf.write(shares[i].tobytes())


def ida_reconstruct_file(output_path: str, share_paths):
    if len(share_paths) == 0:
        raise ValueError("No share files given")
    headers = []
    payloads = []
    for path in share_paths:
        with open(path, "rb") as f:
            header = f.read(16)
            if len(header) < 16:
                raise ValueError(f"Share {path} has invalid header length")
            if header[:4] != b"RIDA":
                raise ValueError(f"Share {path} has invalid magic")
            version = header[4]
            n = header[5]
            m = header[6]
            share_index = header[7]
            (orig_size,) = struct.unpack(">Q", header[8:16])
            data = f.read()
        headers.append((path, version, n, m, share_index, orig_size))
        payloads.append(data)
    _, v0, n0, m0, _, size0 = headers[0]
    for path, v, n, m, _, sz in headers:
        if v != v0 or n != n0 or m != m0 or sz != size0:
            raise ValueError(f"Inconsistent share: {path}")
    n = n0
    m = m0
    orig_size = size0
    if len(share_paths) < m:
        raise ValueError(f"Need at least {m} shares, got {len(share_paths)}")
    used_headers = headers[:m]
    used_payloads = payloads[:m]
    share_indices = [h[4] for h in used_headers]
    share_len = len(used_payloads[0])
    for d in used_payloads:
        if len(d) != share_len:
            raise ValueError("Share payload lengths differ")
    num_blocks = share_len
    data_shares = np.vstack(
        [np.frombuffer(payload, dtype=np.uint8, count=num_blocks) for payload in used_payloads]
    )
    Gm = build_generator_matrix(n, m)
    A = Gm[share_indices, :]
    A_inv = gf_mat_inv(A)
    blocks = np.zeros((num_blocks, m), dtype=np.uint8)
    for j in range(m):
        acc = np.zeros(num_blocks, dtype=np.uint8)
        row = A_inv[j]
        for i in range(m):
            coef = int(row[i])
            acc ^= GF_MUL_TABLE[coef, data_shares[i]]
        blocks[:, j] = acc
    out_bytes = blocks.reshape(-1).tobytes()[:orig_size]
    with open(output_path, "wb") as f:
        f.write(out_bytes)
