"""Ed25519 through the cryptography package when it is installed, else a
pure-Python RFC 8032 implementation (AWP_PURE_ED25519=1 forces it)."""

from __future__ import annotations

import hashlib
import os

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

def _padd(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pmul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _padd(q, pt)
        pt = _padd(pt, pt)
        s >>= 1
    return q


def _pequal(a, b):
    return ((a[0] * b[2] - b[0] * a[2]) % _P == 0 and
            (a[1] * b[2] - b[1] * a[2]) % _P == 0)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 % _P == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(pt) -> bytes:
    zinv = pow(pt[2], _P - 2, _P)
    x = pt[0] * zinv % _P
    y = pt[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512_modl(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _L


def _expand(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def pure_ed25519_public(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_pmul(a, _G))


def pure_ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress(_pmul(a, _G))
    r = _sha512_modl(prefix + msg)
    rs = _compress(_pmul(r, _G))
    h = _sha512_modl(rs + pub + msg)
    s = (r + h * a) % _L
    return rs + int.to_bytes(s, 32, "little")


def pure_ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a_pt = _decompress(pub)
    if a_pt is None:
        return False
    rs = sig[:32]
    r_pt = _decompress(rs)
    if r_pt is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = _sha512_modl(rs + pub + msg)
    return _pequal(_pmul(s, _G), _padd(r_pt, _pmul(h, a_pt)))


try:
    if os.environ.get("AWP_PURE_ED25519", "") not in ("", "0"):
        raise ImportError("pure-Python Ed25519 forced by AWP_PURE_ED25519")
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _SK, Ed25519PublicKey as _PK)
    ED25519_BACKEND = "cryptography"
except ImportError:
    ED25519_BACKEND = "pure-python"


def ed25519_public(seed: bytes) -> bytes:
    if ED25519_BACKEND == "cryptography":
        return _SK.from_private_bytes(seed).public_key().public_bytes(
            _ser.Encoding.Raw, _ser.PublicFormat.Raw)
    return pure_ed25519_public(seed)


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    if ED25519_BACKEND == "cryptography":
        return _SK.from_private_bytes(seed).sign(msg)
    return pure_ed25519_sign(seed, msg)


def ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64 or len(pub) != 32:
        return False
    if ED25519_BACKEND == "cryptography":
        try:
            _PK.from_public_bytes(bytes(pub)).verify(bytes(sig), msg)
            return True
        except (_InvalidSignature, ValueError):
            return False
    return pure_ed25519_verify(bytes(pub), bytes(sig), msg)


